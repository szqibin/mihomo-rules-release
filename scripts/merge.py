import requests
import re
import os
import json

def clean_entry(entry):
    entry = re.sub(r'^(CIDR6|CIDR|IP-CIDR|IP-CIDR6):', '', entry, flags=re.IGNORECASE)
    return entry.strip().strip("'").strip('"')

def is_valid_ip_or_cidr(entry):
    has_digit = any(char.isdigit() for char in entry)
    is_ip_format = ('.' in entry or ':' in entry)
    return has_digit and is_ip_format

def process_content(content, payload_type):
    merged = set()
    entries = re.findall(r"[-]\s*['\"]?([^'\"\s]+)['\"]?", content)
    for e in entries:
        cleaned = clean_entry(e)
        if not cleaned: continue
        if payload_type == "ipcidr":
            if is_valid_ip_or_cidr(cleaned):
                merged.add(cleaned)
        else:
            merged.add(cleaned)
    return merged

def save_source(name, entries, ptype):
    if not entries: return
    os.makedirs("source", exist_ok=True)
    with open(f"source/{name}.list", "w") as f:
        if ptype == "ipcidr":
            for entry in sorted(list(entries)):
                f.write(f"{entry}\n")
        else:
            f.write("payload:\n")
            for entry in sorted(list(entries)):
                f.write(f"  - '{entry}'\n")
    with open(f"source/{name}.type", "w") as f:
        f.write(ptype)
    print(f"  [Success] Generated: source/{name}.list")

def fetch_and_merge():
    # 初始化 source 目录
    if os.path.exists("source"):
        import shutil
        shutil.rmtree("source")
    os.makedirs("source", exist_ok=True)

    # 加载配置
    with open('config.json', 'r') as f:
        config = json.load(f)

    # --- 流程 1：处理 config.json (配置模式) ---
    print("\n[Step 1] Processing config.json...")
    for cat, settings in config['categories'].items():
        merged_entries = set()
        is_ip = any(x in cat.lower() for x in ['cidr', 'lan', 'ip'])
        payload_type = "ipcidr" if is_ip else "domain"
        
        # A. 抓取远程
        for url in settings.get('remote_urls', []):
            try:
                content = requests.get(url, timeout=15).text
                merged_entries.update(process_content(content, payload_type))
            except Exception as e:
                print(f"  Error fetching {url}: {e}")

        # B. 遵循 merge_local 开关
        if settings.get('merge_local', False):
            local_path = os.path.join("custom", f"{cat}.list")
            if os.path.exists(local_path):
                with open(local_path, "r") as f:
                    merged_entries.update(process_content(f.read(), payload_type))
        
        save_source(cat, merged_entries, payload_type)

    # --- 流程 2：处理所有本地文件 (强制生成模式) ---
    print("\n[Step 2] Processing all local files from 'custom' folder...")
    if os.path.exists("custom"):
        for file in os.listdir("custom"):
            if file.endswith(".list"):
                # 排除可能的基础 common 文件
                if file.startswith("common-"): continue
                
                base_name = file.replace(".list", "")
                is_ip = any(x in base_name.lower() for x in ['cidr', 'lan', 'ip'])
                payload_type = "ipcidr" if is_ip else "domain"
                
                # 统一加上 custom_ 前缀，且不与第一步建立任何关联
                target_name = f"custom_{base_name}"
                
                with open(os.path.join("custom", file), "r") as f:
                    local_content = f.read()
                    local_entries = process_content(local_content, payload_type)
                
                save_source(target_name, local_entries, payload_type)
    else:
        print("  'custom' folder not found.")

if __name__ == "__main__":
    fetch_and_merge()

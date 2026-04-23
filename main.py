"""
Phishing Detector - Entry point
"""

import argparse
from src.detector import analyze, check_local_bl
from src.utils import get_domain, resolve_ip


def print_header():
    print("\n" + "=" * 50)
    print("  PHISHING DETECTOR v1.0")
    print("=" * 50 + "\n")


def print_result(result):
    level = result["level"]
    color = "green" if level == "SEGURO" else "red"
    
    print("\n" + "-" * 50)
    print(f"\nURL: {result['url']}")
    print(f"Dominio: {result['domain']}")
    
    if result.get("ip"):
        print(f"  IP: {result['ip']}")
    
    print(f"  Blacklist: {'SI' if result['blacklist'] else 'NO'}")
    
    print("\n" + "=" * 40)
    print(f"  SCORE: {result['score']}")
    print(f"  NIVEL: {result['level']}")
    print("=" * 40)
    
    if result["reasons"]:
        print("\n  RAZONES:")
        for i, r in enumerate(result["reasons"], 1):
            print(f"    {i}. {r}")
    
    print("\n" + "-" * 50)
    if level == "SEGURO":
        print("  [OK] URL parece segura")
    else:
        print("  [X] AMENAZA DETECTADA - NO visitar")
    print("-" * 50 + "\n")


def export_json(results, filename):
    """Exporta a JSON"""
    import json
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"Resultados guardados en: {filename}")


def export_csv(results, filename):
    """Exporta a CSV"""
    import csv
    with open(filename, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["URL", "Dominio", "Score", "Nivel", "IP", "Blacklist", "Razones"])
        for r in results:
            w.writerow([r["url"], r["domain"], r["score"], r["level"], 
                      r.get("ip", ""), r.get("blacklist", False), " | ".join(r["reasons"])])
    print(f"Resultados guardados en: {filename}")


def analyze_batch(urls, output_format="json", output_file="resultados.json"):
    """Analiza múltiples URLs"""
    results = []
    
    for url in urls:
        url = url.strip()
        if not url or url.startswith("#"):
            continue
        
        try:
            result = analyze(url)
            if result:
                results.append(result)
                symbol = "X" if result["level"] == "AMENAZA" else "OK"
                print(f"[{symbol}] {url} -> {result['level']} (score: {result['score']})")
        except Exception as e:
            print(f"[!] Error con {url}: {e}")
    
    if output_format == "json":
        export_json(results, output_file)
    elif output_format == "csv":
        export_csv(results, output_file)
    
    return results


def main():
    parser = argparse.ArgumentParser(description="Phishing Detector")
    parser.add_argument("url", nargs="?", help="URL a analizar")
    parser.add_argument("-f", "--file", help="Archivo con URLs")
    parser.add_argument("-o", "--output", default="resultados.json", help="Archivo de salida")
    parser.add_argument("--csv", action="store_true", help="Exportar a CSV")
    
    args = parser.parse_args()
    
    urls = []
    
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                urls = f.readlines()
        except FileNotFoundError:
            print("Archivo no encontrado")
            return
    elif args.url:
        urls = [args.url]
    
    if urls:
        output_format = "csv" if args.csv else "json"
        
        if len(urls) == 1:
            print_header()
            result = analyze(urls[0])
            if result:
                print_result(result)
        else:
            print(f"Analizando {len(urls)} URLs...\n")
            analyze_batch(urls, output_format, args.output)
    else:
        print_header()
        print("Uso:")
        print("  python3 main.py <URL>                    # Analizar una URL")
        print("  python3 main.py -f <archivo>            # Analizar múltiples URLs")
        print("  python3 main.py -f urls.txt -o out.json   # Guardar a JSON")
        print("  python3 main.py -f urls.txt --csv  # Guardar a CSV")


if __name__ == "__main__":
    main()
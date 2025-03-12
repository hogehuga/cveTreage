#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import ssl
import urllib.request
import urllib.error
import json
import os

class SSLCertificateVerifyFailed(Exception):
    pass

def debug_print(debug, message):
    if debug:
        print("[DEBUG]", message, file=sys.stderr)

def get_vulnrichment_data(cve_id: str, ssl_context=None, debug=False, no_check=False) -> dict:
    # (略) -- ここは従来通りの処理でOK。adp/cnaからCVSSを取得し、"source"キーにadpかcna、またはNAを入れる。

    # 以下はモックの簡易実装例（実際にはユーザ要望どおりadp/cnaを走査する）
    return {
        "cve_id": cve_id,
        "exploitation": "none",
        "automatable": "no",
        "technical_impact": "total",
        "cvss": {
            "baseSeverity": "MEDIUM",
            "baseScore": "6.5",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H"
        },
        "source": "cna"  # adp か cna か NA
    }

def parse_vector_string(vector_str: str) -> dict:
    result = {
        "AV": "NA",
        "AC": "NA",
        "PR": "NA",
        "UI": "NA",
        "S": "NA",
        "C": "NA",
        "I": "NA",
        "A": "NA"
    }
    parts = vector_str.split("/")
    for p in parts[1:]:
        if ":" in p:
            key, val = p.split(":", 1)
            if key in result:
                result[key] = val
    return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-id", "--cve-id", nargs="+")
    parser.add_argument("--no-check-certificate", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-o", "--format", choices=["table", "csv", "tsv"], default="table")
    args = parser.parse_args()

    # (略) -- ここも従来通り: cve_idの取得、ssl_contextの設定など
    cve_list = args.cve_id or []

    results = []
    for cve_id in cve_list:
        info = get_vulnrichment_data(cve_id)
        results.append(info)

    if args.format == "table":
        print_table(results, verbose=args.verbose)
    elif args.format == "csv":
        print_csv(results, verbose=args.verbose, delimiter=",")
    elif args.format == "tsv":
        print_csv(results, verbose=args.verbose, delimiter="\t")

#
# CSV/TSVは従来通り
#
def print_csv(results, verbose=False, delimiter=","):
    if not results:
        return

    if verbose:
        header = [
            "CVE-ID", "baseSeverity", "baseScore", "Exploitation",
            "Automatable", "TechnicalImpact",
            "AV", "AC", "PR", "UI", "S", "C", "I", "A", "source"
        ]
    else:
        header = [
            "CVE-ID", "baseSeverity", "baseScore", "Exploitation",
            "Automatable", "TechnicalImpact", "source"
        ]

    print(delimiter.join(header))

    for row in results:
        cvss = row.get("cvss", {})
        base_sev = cvss.get("baseSeverity", "NA")
        base_score = cvss.get("baseScore", "NA")
        exploitation = row.get("exploitation", "NA")
        automatable = row.get("automatable", "NA")
        tech_impact = row.get("technical_impact", "NA")
        source = row.get("source", "NA")

        if verbose:
            vs = cvss.get("vectorString", "NA")
            parsed = parse_vector_string(vs) if vs != "NA" else {k:"NA" for k in ["AV","AC","PR","UI","S","C","I","A"]}
            line_data = [
                row.get("cve_id", "NA"),
                str(base_sev),
                str(base_score),
                exploitation,
                automatable,
                tech_impact,
                parsed["AV"],
                parsed["AC"],
                parsed["PR"],
                parsed["UI"],
                parsed["S"],
                parsed["C"],
                parsed["I"],
                parsed["A"],
                source
            ]
        else:
            line_data = [
                row.get("cve_id", "NA"),
                str(base_sev),
                str(base_score),
                exploitation,
                automatable,
                tech_impact,
                source
            ]

        print(delimiter.join(line_data))

#
# テーブル出力部(メイン)
#
def print_table(results, verbose=False):
    if not results:
        return

    # 通常モード(-vなし)の列定義: (ヘッダ文字列, カラム幅)
    normal_cols = [
        ("CVE-ID",           16),
        ("Severity",         8),
        ("Score",            5),
        ("Exploitation",     12),
        ("Automatable",      11),
        ("TechnicalImpact",  15),
        ("Source",           6),
    ]

    # verboseモード(-vあり)の列定義:
    # AV, AC, PR, UI, S, C, I, A が幅2
    verbose_cols = [
        ("CVE-ID",           16),
        ("Severity",         8),
        ("Score",            5),
        ("Exploitation",     12),
        ("Automatable",      11),
        ("TechnicalImpact",  15),
        ("AV", 2),
        ("AC", 2),
        ("PR", 2),
        ("UI", 2),
        ("S",  2),
        ("C",  2),
        ("I",  2),
        ("A",  2),
        ("Source",           6),
    ]

    if verbose:
        cols = verbose_cols
    else:
        cols = normal_cols

    # 1) ヘッダ表示: 罫線 → ヘッダ → 罫線
    print_table_border(cols)
    print_table_header(cols)
    print_table_border(cols)

    # 2) データ行
    for row in results:
        cvss = row.get("cvss", {})
        base_sev = cvss.get("baseSeverity", "NA")
        base_score = cvss.get("baseScore", "NA")
        exploitation = row.get("exploitation", "NA")
        automatable = row.get("automatable", "NA")
        tech_impact = row.get("technical_impact", "NA")
        source = row.get("source", "NA")

        if verbose:
            vs = cvss.get("vectorString", "NA")
            parsed = parse_vector_string(vs) if vs != "NA" else {k:"NA" for k in ["AV","AC","PR","UI","S","C","I","A"]}

            row_values = [
                row.get("cve_id", "NA"),
                base_sev,
                base_score,
                exploitation,
                automatable,
                tech_impact,
                parsed["AV"],
                parsed["AC"],
                parsed["PR"],
                parsed["UI"],
                parsed["S"],
                parsed["C"],
                parsed["I"],
                parsed["A"],
                source
            ]
        else:
            row_values = [
                row.get("cve_id", "NA"),
                base_sev,
                base_score,
                exploitation,
                automatable,
                tech_impact,
                source
            ]

        print_table_row(cols, row_values)

    # 3) 最後に罫線
    print_table_border(cols)

#
# 以下、罫線と行表示用の補助関数
#
def print_table_border(columns):
    """
    +--...--+ のような形で列数分つなげて出力する
    """
    # 例: columns = [("CVE-ID",16), ("Severity",8), ...]
    # 幅が16なら、"+----------------"のように+と-を組み合わせる
    border_parts = []
    for _, width in columns:
        border_parts.append("+" + "-" * width)
    border_parts.append("+")  # 行末の +
    print("".join(border_parts))

def print_table_header(columns):
    """
    |CVE-ID          |Severity|Score| ... |Source|
    のように出力
    """
    row_parts = []
    for (col_name, width) in columns:
        # 左詰めでwidth文字ぶん出力
        row_parts.append(f"|{col_name:<{width}}")
    row_parts.append("|")
    print("".join(row_parts))

def print_table_row(columns, values):
    """
    各valuesをcolumnsのwidthに合わせて左詰めし、
    |...|...|...| の形で出力
    """
    row_parts = []
    for i, (col_name, width) in enumerate(columns):
        val = str(values[i])
        row_parts.append(f"|{val:<{width}}")
    row_parts.append("|")
    print("".join(row_parts))

if __name__ == "__main__":
    main()


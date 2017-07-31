import os
import sys
import operator
from collections import defaultdict
from plyara import YaraParser

sys.path.insert(0, os.getcwd())


if __name__ == '__main__':

    file_to_analyze = sys.argv[1]

    with open(file_to_analyze, 'r') as f:
        raw_rules = f.read()

    print("\n[!] Parsing file...")
    parser = YaraParser()
    parsed_rules = parser.run(raw_rules)

    print("\n[!] Analyzing ruleset...")

    authors = defaultdict(int)
    imps = defaultdict(int)
    tags = defaultdict(int)
    meta_keys = defaultdict(int)
    rule_count = 0

    for rule in parsed_rules:
        rule_count += 1

        # Imports
        if 'imports' in rule:
            for imp in rule['imports']:
                imp = imp.replace('"', '')
                imps[imp] += 1

        # Tags
        if 'tags' in rule:
            for tag in rule['tags']:
                tags[tag] += 1

        # Metadata
        if 'metadata' in rule:
            for key in rule['metadata']:
                meta_keys[key] += 1

                # Authors
                if key in ['Author', 'author']:
                    authors[rule['metadata'][key]] += 1

    print("\nNumber of rules in file: {}".format(rule_count))

    sorted_tags = sorted(tags.items(), reverse=True,
                         key=operator.itemgetter(1))

    sorted_imps = sorted(imps.items(), reverse=True,
                         key=operator.itemgetter(1))

    sorted_auths = sorted(authors.items(), reverse=True,
                          key=operator.itemgetter(1))

    sorted_meta = sorted(meta_keys.items(), reverse=True,
                         key=operator.itemgetter(1))

    top_range = 10

    if sorted_meta:
        print("\nTop {} metadata keys:".format(top_range))
        for i in range(top_range):
            if i < len(sorted_meta):
                print("\t{}".format(sorted_meta[i]))

    if sorted_auths:
        print("\nTop {} authors:".format(top_range))
        for i in range(top_range):
            if i < len(sorted_auths):
                print("\t{}".format(sorted_auths[i]))

    if sorted_imps:
        print("\nTop {} imports:".format(top_range))
        for i in range(top_range):
            if i < len(sorted_imps):
                print("\t{}".format(sorted_imps[i]))

    if sorted_tags:
        print("\nTop {} tags:".format(top_range))
        for i in range(top_range):
            if i < len(sorted_tags):
                print("\t{}".format(sorted_tags[i]))

    print("\n")

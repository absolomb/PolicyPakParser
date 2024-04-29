import xml.etree.ElementTree as ET
import argparse
import sys

def get_element_text(element):
    return element.text if element is not None else ''

def parse_filter_text(filter_text, indent=0):

    if filter_text:
        if type(filter_text) == str:
    
            filter_tree = ET.fromstring(filter_text)
        else:
            filter_tree = filter_text
        
        formatted_filters = []
        
        for child in filter_tree:
            if child.tag == 'FilterComputer':
                bool_value = child.get('bool', '')
                not_value = child.get('not', '')
                type_value = child.get('type', '')
                name_value = child.get('name', '')
                if not_value == "1":
                    filter_component = f"\n     NOT Computer ({type_value}): {name_value}\n"
                else:
                    filter_component = f"\n     Computer ({type_value}): {name_value}\n"
                formatted_filters.append(filter_component)
            
            elif child.tag == 'FilterGroup':
                bool_value = child.get('bool', '')
                not_value = child.get('not', '')
                name_value = child.get('name', '')
                sid_value = child.get('sid', '')
                
                if not_value == "1":
                    filter_component = f"\n     NOT Group ({bool_value}): {name_value} (SID: {sid_value})\n"
                else:
                    filter_component = f"\n     Group ({bool_value}): {name_value} (SID: {sid_value})\n"
                formatted_filters.append(filter_component)

            elif child.tag == 'FilterUser':
                bool_value = child.get('bool', '')
                not_value = child.get('not', '')
                name_value = child.get('name', '')
                sid_value = child.get('sid', '')
                if not_value == "1":
                    filter_component = f"\n     NOT User ({bool_value}): {name_value} (SID: {sid_value})\n"
                
                else:
                    filter_component = f"\n     User ({bool_value}): {name_value} (SID: {sid_value})\n"
                formatted_filters.append(filter_component)

            elif child.tag == 'FilterCollection':
                bool_value = child.get('bool', '')
                not_value = child.get('not', '')
                filter_component = f"'\n     Collection ({bool_value}):"
                filter_component2 = parse_filter_text(child, indent + 1)
                if filter_component2:
                    filter_component += filter_component2
                
                formatted_filters.append(filter_component)
            else:
                print("unhandled filter")
                print(filter_text)
        
        return ' '.join(formatted_filters)

def parse_policy_entry(entry, show_disabled):
    order = entry.get('order')
    scope = entry.get('scope')
    displayName = entry.get('displayName')
    disabled = entry.get('disabled')

    if disabled is None:
        disabled = "false"
    
    if not show_disabled and disabled == "true":
        print("[-] Skipping disabled rule")
        return

    comment = get_element_text(entry.find('{http://www.policypak.com/2016/LPM/PolicyData}comment'))
    filter_text = get_element_text(entry.find('{http://www.policypak.com/2016/LPM/PolicyData}filter'))
    filter_text = parse_filter_text(filter_text)
    print(f"[*] Display Name: {displayName}")
    print(f"    Order: {order}, Scope: {scope}") 
    print(f"    Disabled: {disabled}")
    print(f"    Comment: {comment}")
    print(f"    Entry Filter: {filter_text}")

    rule_v1 = entry.find('{http://www.policypak.com/2016/LPM/PolicyData}rule-v1')
    if rule_v1 is not None:
        conditions = rule_v1.find('.//{http://www.policypak.com/2016/LPM/ExecutableRule}conditions')
        if conditions is not None:
            for condition in conditions:
                if 'Condition' in condition.tag:
                    if 'signatureCondition' in condition.tag:
                        description = get_element_text(condition.find('{http://www.policypak.com/2016/LPM/Rules}commonName'))
                        value = get_element_text(condition.find('{http://www.policypak.com/2016/LPM/Rules}fileInfoCondition'))
                        print(f"    Signature Condition - Common Name: {description}")
                        print(f"    File Info Condition: {value}")
                    elif 'fileInfoCondition' in condition.tag:
                        product_name = get_element_text(condition.find('{http://www.policypak.com/2016/LPM/Rules}productName'))
                        product_version_tag = condition.find('{http://www.policypak.com/2016/LPM/Rules}productVersion')
                        product_version = get_element_text(product_version_tag)
                        product_version_mode = product_version_tag.get('mode', '')
                        filename_version_tag = condition.find('{http://www.policypak.com/2016/LPM/Rules}fileVersion')
                        fileVersion = get_element_text(filename_version_tag)
                        filename_version_mode = filename_version_tag.get('mode', '')
                        fileName = get_element_text(condition.find('{http://www.policypak.com/2016/LPM/Rules}fileName'))
                        print(f"    Product Name: {product_name}")
                        print(f"    Product Version: {product_version_mode} {product_version}")
                        print(f"    File Name: {fileName}")
                        print(f"    File Version: {filename_version_mode} {fileVersion}")
                    elif 'fileHashCondition' in condition.tag:
                        description = get_element_text(condition.find('{http://www.policypak.com/2016/LPM/Rules}description'))
                        value = get_element_text(condition.find('{http://www.policypak.com/2016/LPM/Rules}value'))
                        print(f"    File Hash Condition - Description: {description}")
                        print(f"    File Hash Value: {value}")
                    elif 'pathCondition' in condition.tag:
                        paths = condition.findall('{http://www.policypak.com/2016/LPM/Rules}path')
                        for path in paths:
                            path_kind = path.get('kind')
                            path_text = get_element_text(path)
                            print(f"    Path Condition - Kind: {path_kind}, Path: {path_text}")
                    elif 'commandLineCondition' in condition.tag:
                        value = get_element_text(condition.find('{http://www.policypak.com/2016/LPM/Rules}value'))
                        useAndSpecifier = get_element_text(condition.find('{http://www.policypak.com/2016/LPM/Rules}useAndSpecifierForArguments'))
                        print(f"    Command Line Condition - Value: {value}")
                        print(f"    Use AND Specifier for Arguments: {useAndSpecifier}")
                    else:
                        print("    Unknown Condition type")

    secure_run_rule_element = entry.find('.//{http://www.policypak.com/2016/LPM/Rules-V1}secureRunRule')
    if secure_run_rule_element is not None:
        options_element = secure_run_rule_element.find('{http://www.policypak.com/2016/LPM/SecureRunRule}options')
        conditions_element = secure_run_rule_element.find('{http://www.policypak.com/2016/LPM/SecureRunRule}conditions')
        file_ownership_element = conditions_element.find('{http://www.policypak.com/2016/LPM/Rules}fileOwnershipCondition')
        trusted_owner_element = file_ownership_element.find('{http://www.policypak.com/2016/LPM/Rules}trustedOwners')
        trusted_owners = trusted_owner_element.findall('{http://www.policypak.com/2016/LPM/Rules}trustedOwner')
        enabled_trusted_ownership = options_element.find('{http://www.policypak.com/2016/LPM/SecureRunRule}enableTrustedOwnershipChecking').text
        change_when_overwritten = options_element.find('{http://www.policypak.com/2016/LPM/SecureRunRule}changeWhenOverwritten').text

        trusted_owners_list = []
        if trusted_owners is not None:
            for trusted in trusted_owners:
                display_name = trusted.get('displayName', '')
                sid = trusted.get('sid', '')
                trusted_owners_list.append({'displayName': display_name, 'sid': sid})


        print(f"    Enable Trusted Ownership Checking: {enabled_trusted_ownership}")
        print(f"    Change When Overwritten: {change_when_overwritten}")
        print("    Trusted Owners:")
        for owner in trusted_owners_list:
            print(f"      Display Name: {owner['displayName']}, SID: {owner['sid']}")


def main():

    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-d',  help="Show disabled rules (Default: false)", action='store_true', default=False)
    parser.add_argument('-f', help="PolicyData.xml file to parse", type=str)

    args = parser.parse_args()
    if len(sys.argv) == 1:
            parser.print_help()
            exit()

    filename = args.f
    show_disabled = args.d

    tree = ET.parse(filename)
    root = tree.getroot()


    namespaces = {
        'common16': 'http://www.policypak.com/2016/LPM/CommonTypes',
        'ext': 'http://www.policypak.com/2019/LPM/PolicyEntryExtension',
        'sec': 'http://www.policypak.com/2016/LPM/Security',
        'pd14': 'http://www.policypak.com/2014/Policies/PolicyData',
        'common14': 'http://www.policypak.com/2014/CommonTypes',
        'default': 'http://www.policypak.com/2016/LPM/PolicyData'
    }

    for collection in root.findall('.//default:collection', namespaces):
        for entry in collection.findall('./default:entry', namespaces):
            print(f"[*] Collection: {collection.get('displayName')}")
            filter_text = get_element_text(collection.find('{http://www.policypak.com/2016/LPM/PolicyData}filter'))
            filter_text = parse_filter_text(filter_text)
            print(f"    Collection Filter: {filter_text}\n")
            parse_policy_entry(entry, show_disabled)
            print('\n'+'=' * 50) 


if __name__ == "__main__":
    main()
import argparse
import json
import xml.etree.ElementTree as ET

from parser import SbomParser
import vulners


def open_json(filename):
    with open(filename, 'r') as fp:
        try:
            return json.load(fp)
        except json.JSONDecodeError as err:
            print(err.msg)


def open_xml(filename):
    try:
        tree = ET.parse(filename)
        return tree.getroot()
    except ET.ParseError as err:
        print(err.msg)


if __name__ == '__main__':

    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument("-i","--input", required=True, help="Input file name. Supported formats: CycloneDX json or xml, SPDX json or Syft json")
    arg_parser.add_argument("-k","--apikey", required=True, help="Vulners api key. "
                                           "You can generate it here https://vulners.com/userinfo with 'api' scope")
    arg_parser.add_argument("-o", "--output", help="Output file name")
    args = arg_parser.parse_args()

    packages = []
    os_data = {}
    _data = None

    api = vulners.VulnersApi(api_key=args.apikey)

    if args.input.endswith(".json"):
        _data = open_json(args.input)

    if args.input.endswith(".xml"):
        _data = open_xml(args.input)

    if not _data:
        print("Cannot read file ", args.input)
        exit(1)

    for klass in SbomParser.__subclasses__():
        parser = klass()
        if parser.test_file_format(_data):
            packages = parser.get_packages(_data)
            os_data = parser.get_os_info(_data)
            break

    if packages and os_data:
        api_result = api.os_audit(os=os_data['name'], version=os_data['version'], packages=packages)

        print(f"Operation System: {os_data['name']} {os_data['version']}")
        print(f"Found {len(api_result['vulnerabilities'])} vulnerabilities")
        print('-'*60)
        print("{:<40}".format("Package"), "CVEs")
        print('-' * 60)
        for reason in api_result['reasons']:
            print("{:<40}".format(reason['package']), ', '.join(reason['cvelist']))

    else:
        print(f"Error in file {args.filename}.")
        print("Unsupported file format. Please use one of CycloneDX json or xml, SPDX json or Syft json")

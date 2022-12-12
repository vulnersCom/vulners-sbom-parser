
import xml.etree.ElementTree as ET
import re


class SbomParser:
    templates = {
        'pkg:deb': '{name} {version} {arch}',
        'pkg:rpm': '{name}-{version}.{arch}'
    }

    def get_name(self, component):
        return component['name']

    def get_version(self, component):
        return component['version']

    def get_purl(self, component):
        return component['purl']

    def get_components(self, data):
        return []

    def test_file_format(self, data):
        return False

    @staticmethod
    def is_json(data):
        return type(data) == dict

    @staticmethod
    def is_xml(data):
        return type(data) == ET.Element

    @staticmethod
    def log(message):
        print(message)

    def get_package_info(self, name: str, version: str, purl: str):
        package_type = purl.split('/')[0]
        if package_type not in self.templates:
            return
        arch = re.search(r'arch=(.*?)&', purl).group(1)
        return (self.templates[package_type].format(name=name,
                                                    version=version,
                                                    arch=arch))

    def get_packages(self, data):
        if not self.test_file_format(data):
            self.log("Wrong file format")
            return
        result = []
        for component in self.get_components(data):
            if package := self.get_package_info(self.get_name(component),
                                                self.get_version(component),
                                                self.get_purl(component)):
                result.append(package)
        return result

    def get_os_info(self, data):
        return {
            'name': "Unknown",
            'version': ''
        }


class SpdxJsonParser(SbomParser):
    def get_purl(self, component):
        return next(ref['referenceLocator'] for ref in component['externalRefs']
                    if ref["referenceType"] == "purl")

    def get_version(self, component):
        return component['versionInfo']

    def get_components(self, data):
        return data['packages']

    def test_file_format(self, data):
        if not self.is_json(data):
            return False
        file_version = data.get('spdxVersion', '')
        return 'SPDX-2.2' in file_version

    def get_os_info(self, data):
        for component in self.get_components(data):
            purl = self.get_purl(component)
            if 'distro' in purl:
                name, version = purl.split('distro=')[-1].split('-')
                return {
                    'name': name,
                    'version': version
                }
        else:
            return super().get_os_info(data)


class SyftSbomParser(SbomParser):
    def get_components(self, data):
        return data['artifacts']

    def test_file_format(self, data):
        if not self.is_json(data):
            return False
        schema = data.get('schema', {}).get('url', '')
        return 'anchore/syft/main/schema/json' in schema

    def get_os_info(self, data):
        if 'distro' in data:
            return {
                'name': data['distro']['name'],
                'version': data['distro']['versionID']
            }
        else:
            return super().get_os_info(data)


class CycloneDXJsonParser(SbomParser):
    def test_file_format(self, data):
        if not self.is_json(data):
            return False
        bomFormat = data.get('bomFormat', '')
        return 'CycloneDX' in bomFormat

    def get_components(self, data):
        return filter(lambda x: 'library' in x.get('type'), data['components'])

    def get_os_info(self, data):
        os_info = next(filter(lambda x: 'operating-system' in x.get('type'), data['components']))
        if os_info:
            return {
                'name': os_info['name'],
                'version': os_info['version']
            }
        else:
            return super().get_os_info(data)


class CycloneDXXmlParser(SbomParser):
    namespaces = {'bom': 'http://cyclonedx.org/schema/bom/1.4'}

    def test_file_format(self, data):
        if not self.is_xml(data):
            return False
        return data.tag == '{http://cyclonedx.org/schema/bom/1.4}bom'

    def get_name(self, component):
        return component.find('bom:name', self.namespaces).text

    def get_version(self, component):
        return component.find('bom:version', self.namespaces).text

    def get_purl(self, component):
        return component.find('bom:purl', self.namespaces).text

    def get_components(self, data):
        return filter(lambda x: 'library' in x.get('type'),
                      data.findall("./bom:components/bom:component", self.namespaces))

    def get_os_info(self, data):
        os_info = next(filter(lambda x: 'operating-system' in x.get('type'),
                              data.findall("./bom:components/bom:component", self.namespaces)))
        if os_info:
            return {
                'name': os_info.find('bom:name', self.namespaces).text,
                'version': os_info.find('bom:version', self.namespaces).text
            }
        else:
            return super().get_os_info(data)




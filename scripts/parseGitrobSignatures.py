# -*- coding: utf-8 -*-
# __version__ = '0.2'

import json


def read_json_file(path):
    """
    Func for store json formatted data to local file
    :param path: string
    :return: none
    """
    try:
        return json.loads(open(path).read())
    except IOError:
        print("File is missed. Please check")


def write_to_file(filename, data):
    """
    Func for store dictionary to local file
    :param filename: string
    :param data: dictionary
    :return: None
    """
    json_outfile = open(filename, 'w')
    json_outfile.write(data)
    json_outfile.close()


def main():
    """

    :return:
    """
    signatures = read_json_file('gitrob-signatures.txt')
    converted = ''
    for signature in signatures:
        regex = signature['pattern'].replace('\\A', '').replace('\\z', '').replace('\.?', '.?')
        line = '"{0}": re.compile(\'{1}\'),\n'.format(signature['caption'], regex)
        converted += line
    # print converted
    write_to_file('converted_gitron.txt', converted)
    return converted



if __name__ == '__main__':
    main()
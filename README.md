CEFS: CentOS Errata for Spacewalk
====

## Overview

This repository contains my work around CEFS.
It currently consists of the following pieces:

- _errata-import.pl_: The import script that will read XML and write to Spacewalk (or a compatible) API
- _errata-wipe.pl_: A script to remove all existing errata data from Spacewalk (or a compatible) API
- _xml2json.pl_: A script to convert the ugly XML data structure into a nicer JSON form.
- _yum-history-html.pl_: A script to convert the YUM history into HTML and enrich it with errata information.

- _errata.latest.xml_: The latest information on Errata for CentOS (supported versions only)
- _errata.latest.json_: The same data as in the XML, but in JSON format (a derivative)

## License

The data files (errata.latest.xml and errata.latest.json) are licensed CC BY-NC-ND.

See https://creativecommons.org/licenses/by-nc-nd/4.0/

The most recent versions of the data files can be found on the project homepage
at https://cefs.steve-meier.de. The versions in this repository may be outdated.

Any scripts in this repository are licensed under the MIT License.

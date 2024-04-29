### Description
Small tool to parse PolicyPak PolicyData.xml files which are stored in Group Policy folders. This is useful to help quickly display rulesets applied in a more easily readable format.

### Usage
All that is required is the filename.
```
python parser.py -f PolicyData.xml
```
By default rules which are marked as "disabled" are filtered out to reduce noise. This can be overridden with the `-d` option.

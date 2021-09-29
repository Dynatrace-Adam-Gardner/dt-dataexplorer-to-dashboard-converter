# dt-dataexplorer-to-dashboard-converter

Take the output of Dynatrace Data Explorer code, save as code and transform to a DT dashboard with this tool.

## Step 1
![image](https://user-images.githubusercontent.com/13639658/135361728-471ef9e8-f08a-4908-a1cf-278e253db981.png)

## Step 2
Save as a YAML file:
![image](https://user-images.githubusercontent.com/13639658/135361765-56dd5ca6-3cca-4e05-bd2a-276b8c91a49a.png)

## Step 3
![image](https://user-images.githubusercontent.com/13639658/135361816-d2a87b95-7a6c-4561-9351-e909a0747482.png)

## Prereqs
```
pip install pyyaml
```

## Usage

```
set input_file=sli.yaml
# Optional
# set debug=true
python app.py
```

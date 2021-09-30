# dt-dataexplorer-to-dashboard-converter

Take the output of Dynatrace Data Explorer code, save as code and transform to a DT dashboard with this tool.

## Step 1
![image](https://user-images.githubusercontent.com/13639658/135363280-ed62bfc5-6400-4a1d-a351-aa4b45861075.png)

## Step 2
Save as a YAML file:
![image](https://user-images.githubusercontent.com/13639658/135363242-33ac80ba-a5b0-454e-95f4-ca2cd6be9012.png)

## Step 3
![image](https://user-images.githubusercontent.com/13639658/135363326-7d7c2693-e054-42ac-b217-2f5fd5c31012.png)

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

## TODO List
1. ✅ Support `limit` (done)
2. ✅ Support `splitBy` (done)
3. Support filtering
4. Add additional params for dashboard name etc
5. Dockerise app

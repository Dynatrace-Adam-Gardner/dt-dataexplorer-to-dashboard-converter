import json
import os
import yaml
import re

# TODO
# Support limit (DONE)
# Support splitBy (DONE)
# Support filters

#
# Prerequisites
# pip install PyYAML
#

#
# Usage
# set input_file=sli.yaml
# set DEBUG=true
# python app.py
#

class Object:
    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=2)

def remove_quotes_from_list(list):
  print(f'Input List: {list}')
  new_list = []
  for item in list:
    if '"' in item:
      # Found a quotation in list item. Removing
      item = item.replace('"','')
    new_list.append(item)
  
  print(f'Returning cleaned list: {new_list}')
  return new_list

def readSLIFile(filename):
  sli_file = ""
  with open(filename, "r") as stream:
    try:
        sli_file = yaml.safe_load(stream)
        #print(yaml.safe_load(stream))
    except yaml.YAMLError as exc:
        print(exc)

  return sli_file

def generateDashboard(sli_file):
  slis = sli_file.get('indicators')
  for sli in slis:
    #print(sli)
    sli_def = slis.get(sli)
    #print(sli_def)

  number_of_slis = str(len(slis))
  if DEBUG:
    print(f'Need to create {number_of_slis} tiles on the dashboard')
    print('-------')

  TILE_PIXELS = 38 # A 1x1 tile is 38x38
  TILE_WIDTH = 7
  TILE_HEIGHT = 7
  # Minimum tile dimensions to get axis
  #   width=7*TILE_WIDTH, height=7*TILE_WIDTH
  # On graph tile: 7x7
  # On single value tile: 6x6

  dashboard = Object()
  dashboard.id = "62eeba9e-b23b-46c7-b3c4-cef18222c281"
  dashboard.dashboardMetadata = Object()
  dashboard.dashboardMetadata.name = "trivy dashboard 2"
  dashboard.dashboardMetadata.owner = "adam.gardner@dynatrace.com"
  dashboard.dashboardMetadata.shared = False

  tiles = []

  loop_count = 0

  for sli in slis:
    if DEBUG:
      print(loop_count)
    sli_name = sli
    sli_def = slis.get(sli)

    # sli_def comes in as 'trivy.vulnerabilities.CRITICAL:splitBy():avg:auto:sort(value(avg,descending)):limit(100)'
    # or 'builtin:apps.web.actionCount.category:splitBy():avg:auto:sort(value(avg,descending)):limit(100)'
    # Trim to :splitBy
    trimmed_sli_def = sli_def[:sli_def.index(':splitBy')]
    
    # Get limit value
    limit_value_string = sli_def[sli_def.index(':limit(')+7:-1]
    limit_value = int(limit_value_string)

    # Get splitBy values
    print(sli_def)
    match = re.search('splitBy\((.*?)\)',sli_def) # Get values between :splitBy(...)
    print(match)
    print(f'Group 1 Match: {match.group(1)}')
    # match.group(1) will be an empty string if the SLI has splitBy()
    # Otherwise it'll be a CSV of split values
    split_list = []
    if match.group(1) != "":
      split_list = match.group(1).split(',')

    split_list = remove_quotes_from_list(split_list)
    print(f'Split List: {split_list}')

    if DEBUG:
      print(f'SLI Name: {sli_name}')
      print(f'Full SLI Definition (untrimmed): {sli_def}')
      print(f'Trimmed SLI Definition: {trimmed_sli_def}')
      print(f'Limit Value: {limit_value_string}')
      print(f'Split List: {split_list}')
      print('-----')
    
    tile_pixel_width = TILE_WIDTH*TILE_PIXELS
    tile_pixel_height = TILE_HEIGHT*TILE_PIXELS

    tile = Object()
    tile.name = "sli=" + sli_name
    tile.tileType = "DATA_EXPLORER"
    tile.customName = "Data explorer results"
    tile.configured = True
    tile.bounds = Object()

    # If this is the first tile, top and left is 0
    # Otherwise it is 'loop_count * tile_width'
    # tile bounds must be divisible by 38
    tile.bounds.top = 0
    if loop_count > 0:
      tile.bounds.left = loop_count * tile_pixel_width
    else:
      tile.bounds.left = 0
    tile.bounds.width = tile_pixel_width
    tile.bounds.height = tile_pixel_height

    tiles.append(tile)
  
    tileFilter = Object()
    tile.tileFilter = tileFilter

    queries = []

    query = Object()
    query.id = "A"
    query.metric = trimmed_sli_def
    query.spaceAggregation = "AVG"
    query.timeAggregation = "DEFAULT"
    query.splitBy = []
    query.filterBy = Object()
    query.filterBy.nestedFilters = []
    query.filterBy.criteria = []
    query.enabled = True
    query.limit = limit_value
    query.splitBy = split_list

    queries.append(query)
    tile.queries = queries

    visualConfig = Object()
    visualConfig.rules = []
    tile.visualConfig = visualConfig
    #visualConfig.type = "SINGLE_VALUE" # Single value chart type
    visualConfig.type = "GRAPH_CHART" # standard line chart type
    globalObj = Object()
    visualConfig.globalx = globalObj
    globalObj.theme = "DEFAULT"
    globalObj.seriesType = "LINE"

    #threshold = Object()
    #globalObj.threshold = threshold
    #threshold.axisTarget = "LEFT"
    #threshold.rules = []
    #rule1 = Object()
    #rule1.color = "#ffb00f"
    #rule2 = Object()
    #rule2.color = "#f5d30f"
    #rule3 = Object()
    #rule3.color = "#dc172a"
    #threshold.rules.append(rule1)
    #threshold.rules.append(rule2)
    #threshold.rules.append(rule3)

    xAxes = Object()
    xAxes.displayName = ""
    xAxes.visible = True

    yAxes = []
    yAxes1 = Object()
    yAxes1.displayName = ""
    yAxes1.visible = True
    yAxes1.min = "AUTO"
    yAxes1.max = "AUTO"
    yAxes1.position = "LEFT"
    yAxes1.defaultAxis = True
    yAxes1.queryIds = []
    yAxes1.queryIds.append("A")

    yAxes.append(yAxes1)

    visualConfig.axes = Object()
    visualConfig.axes.xAxis = xAxes
    visualConfig.axes.yAxes = yAxes

    loop_count += 1

  dashboard.tiles = tiles

  dashboardJSON = dashboard.toJSON()
  dashboardJSON = dashboardJSON.replace("globalx","global")
  return dashboardJSON

## Get Input param
sli_file_name = os.environ.get('input_file')
debug_flag = os.environ.get('debug')
DEBUG = False
if debug_flag in ["true", "T", "TRUE", "True", "1"]:
  DEBUG = True

if DEBUG:
  print('debug mode is on')
  print(f'Input filename: {sli_file_name}')


## Call Methods Here...
sli_file = readSLIFile(sli_file_name)
dashboardJSON = generateDashboard(sli_file)

print(dashboardJSON)

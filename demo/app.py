import json
import os
import yaml
import re

# TODO
# Support limit (DONE)
# Support splitBy (DONE)
# Support filters (partial - supports a single filter)

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
      remove_quotes_from_string(item)
    new_list.append(item)
  
  if DEBUG:
    print(f'Returning cleaned list: {new_list}')
  return new_list

def remove_quotes_from_string(item):
  if '"' in item:
    item = item.replace('"','')
  
  if DEBUG:
    print(f'Returning cleaned string: {item}')
  return item
    
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
    # or with filter() first
    # or 'builtin:apps.web.actionCount.category:splitBy():avg:auto:sort(value(avg,descending)):limit(100)'
    # Trim to :splitBy
    # So get index of :splitBy and index of :filter
    # Whichever is lower, use that
    trim_index = -1
    split_by_index = sli_def.index(':splitBy')
    filter_by_index = sli_def.index(':filter')
    print(f'Split By Index: {split_by_index}')
    print(f'Filter By Index: {filter_by_index}')
    if split_by_index < filter_by_index:
      if DEBUG:
        print('split_by_index is lower than filter_by_index (splitBy() comes first in SLI) so using split_by_index')
      trim_index = split_by_index
    else:
      trim_index = filter_by_index
      if DEBUG:
        print('filter_by_index is lower than split_by_index (filter(...) comes first in SLI) so using filter_by_index')
    
    if DEBUG:
      print(f'Split By Index: {split_by_index}')
      print(f'Filter By Index: {filter_by_index}')

    trimmed_sli_def = sli_def[:trim_index]
    
    # Get limit value
    limit_match = re.search('limit\((.*?)\)',sli_def) # Get values between :limit(...)
    limit_value_string = ""
    limit_value = 10 # Default to 10
    if limit_match != None:
      limit_value_string = limit_match.group(1)
      limit_value = int(limit_value_string)

    # Get splitBy values
    split_by_match = re.search('splitBy\((.*?)\)',sli_def) # Get values between :splitBy(...)
    # split_by_match.group(1) will be an empty string if the SLI has splitBy()
    # Otherwise it'll be a CSV of split values
    split_list = []
    if split_by_match != None and split_by_match.group(1) != "":
      split_list = split_by_match.group(1).split(',')

    split_list = remove_quotes_from_list(split_list)
    print(f'Split List: {split_list}')

    # Get Filter
    filter = ""
    filter_match = re.search('filter\(([^:]+)', sli_def)
    if filter_match != None and filter_match.group(1) != "":
      filter = filter_match.group(1)

    if DEBUG:
      print(f'SLI Name: {sli_name}')
      print(f'Full SLI Definition (untrimmed): {sli_def}')
      print(f'Trimmed SLI Definition: {trimmed_sli_def}')
      print(f'Limit Value: {limit_value}')
      print(f'Split List: {split_list}')
      if filter != "": print(f'Filter: {filter}')
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
    print(f'Printing Trimmed SLI Def: {trimmed_sli_def}')
    query.metric = trimmed_sli_def
    query.spaceAggregation = "AVG"
    query.timeAggregation = "DEFAULT"
    query.splitBy = []
    query.filterBy = Object()

    # Get filter condition
    # This is one of [AND, OR, NOT] case sensitive
    filterOperatorUppercase = ""
    if filter != "":
      query.filterBy.filterOperator = ""
      filterOperatorUppercase = filter[:filter.index('(')].upper()
      print(f'Filter Operator Uppercase:  {filterOperatorUppercase}')
      query.filterBy.filterOperator = filterOperatorUppercase
    query.filterBy.nestedFilters = []
    if filter != "":
      nestedFilter = Object()
      query.filterBy.nestedFilters.append(nestedFilter)
      nestedFilter.filterType = "DIMENSION"
      nestedFilter.filterOperator = "OR"

      nestedFilter.criteria = []
      nested_filter_criteria = Object()
      nestedFilter.criteria.append(nested_filter_criteria)


      # Get filter value eg. 'tag' in tag=nginx
      # Assumes tag filter is equals ie. eq
      filter_value = ""
      filter_value = filter[filter.index('eq(')+3:filter.index(',')]
      if filter_value != "":
        print(f'Filter Value: {filter_value}')

        filter_value_match = re.search(filter_value+',([^)]+)',filter)
        if filter_value_match != None and filter_value_match.group(1) != "":
          # Get filter criteria value eg. 'nginx' in tag=nginx
          filter_criteria_value = remove_quotes_from_string(filter_value_match.group(1))
          print(f'Filter Criteria Value: {filter_criteria_value}')
          nested_filter_criteria.value = filter_criteria_value
          nested_filter_criteria.evaluator = "EQ" # Assumes equals...


      nestedFilter.filter = filter_value
    # match.group(1) will be an empty string if the SLI has splitBy()
    # Otherwise it'll be a CSV of split values
    split_list = []
    if split_by_match != None and split_by_match.group(1) != "":
      split_list = split_by_match.group(1).split(',')
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
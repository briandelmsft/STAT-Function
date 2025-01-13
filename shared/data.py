import pandas as pd
import copy
import pathlib
import json
import os

date_format = os.getenv('DATE_FORMAT')
tz_info = os.getenv('TIME_ZONE')

def list_to_html_table(input_list:list, max_rows:int=20, max_cols:int=10, nan_str:str='N/A', escape_html:bool=True, columns:list=None, index:bool=False, justify:str='left', drop_empty_cols:bool=False):
    '''Convert a list of dictionaries into an HTML table'''
    df = pd.DataFrame(input_list)
    df.index = df.index + 1

    if drop_empty_cols:
        all_cols = df.columns.values.tolist()
        to_drop = []

        for col in all_cols:
            if all(df[col] == ''):
                to_drop.append(col)
            
        if to_drop:
            df.drop(labels=to_drop, axis=1, inplace=True)
        df.dropna(axis=1, how='all', inplace=True)

    if date_format or tz_info:
        try:
            time_columns = ['TimeGenerated','Timestamp','StartTime','EndTime','activityDateTime','FirstSeen','LastSeen']
            df_time = df.copy(deep=True)
            for time_col in time_columns:
                if time_col in df.columns:
                    df_time[time_col] = pd.to_datetime(df_time[time_col])

                if tz_info:
                    if time_col in df.columns:
                        df_time[time_col] = df_time[time_col].dt.tz_convert(tz_info)

                if date_format:
                    if time_col in df.columns:
                        df_time[time_col] = df_time[time_col].dt.strftime(date_format)
        except:
            html_table = df.to_html(max_rows=max_rows, max_cols=max_cols, na_rep=nan_str, escape=escape_html, columns=columns, index=index, justify=justify).replace('\n', '')
        else:
            html_table = df_time.to_html(max_rows=max_rows, max_cols=max_cols, na_rep=nan_str, escape=escape_html, columns=columns, index=index, justify=justify).replace('\n', '')
    else:
        html_table = df.to_html(max_rows=max_rows, max_cols=max_cols, na_rep=nan_str, escape=escape_html, columns=columns, index=index, justify=justify).replace('\n', '')

    return html_table

def update_column_value_in_list(input_list:list, col_name:str, update_str:str):
    '''Updates the value of a column in each dict in the list with a value from another column, to include the column value in your replacement use [col_value]'''
    updated_list = []
    for row in input_list:
        current_row = copy.copy(row)
        current_row[col_name] = update_str.replace('[col_value]', current_row[col_name])
        updated_list.append(current_row)

    return updated_list

def replace_column_value_in_list(input_list:list, col_name:str, original_value:str, replacement_value:str):
    '''Updates the value of a column in each dict in the list, with a static value'''
    updated_list = []
    for row in input_list:
        current_row = copy.copy(row)
        current_row[col_name] = current_row[col_name].replace(original_value, replacement_value)
        updated_list.append(current_row)

    return updated_list

def return_highest_value(input_list:list, key:str, order:list=['High','Medium','Low','Informational','None','Unknown']):
    '''Locate the highest value in a list of dictionaries by key'''
    
    unsorted_list = []
    for item in input_list:
        unsorted_list.append(item[key].lower())

    for item in order:
        if item.lower() in unsorted_list:
            return item
    
    return 'Unknown'

def join_lists(left_list, right_list, kind, left_key, right_key, fill_nan=None):
    '''Join 2 lists of objects using a key.  Supported join kinds left, right, outer, inner, cross'''
    left_df = pd.DataFrame(left_list)
    right_df = pd.DataFrame(right_list)
    join_data = left_df.merge(right=right_df, how=kind, left_on=left_key, right_on=right_key)
    if fill_nan is None:
        join_data = join_data.where(join_data.notna(), None)
    else:
        join_data = join_data.fillna(fill_nan)

    return join_data.to_dict('records')

def sum_column_by_key(input_list, key):
    df = pd.DataFrame(input_list)
    try:
        val = int(df[key].sum())
    except KeyError:
        val = int(0)
    return val

def max_column_by_key(input_list, key):
    df = pd.DataFrame(input_list)
    try:
        val = int(df[key].max())
    except KeyError:
        val = int(0)
    return val

def min_column_by_key(input_list, key):
    df = pd.DataFrame(input_list)
    try:
        val = int(df[key].min())
    except KeyError:
        val = int(0)
    return val

def sort_list_by_key(input_list, key, ascending=False):
    df = pd.DataFrame(input_list)
    df = df.sort_values(by=[key], ascending=ascending)
    return df.to_dict('records')

def coalesce(*args):
    for arg in args:
        if arg is not None:
            return arg
        
def version_check(current_version:str, avaialble_version:str, update_check_type:str):
    
    if current_version == 'Unknown':
        return {'UpdateAvailable': False, 'UpdateType': 'None'}
    
    current = current_version.split('.')
    available = avaialble_version.split('.')

    update_dict = {
        'Major': 1,
        'Minor': 2,
        'Build': 3
    }

    if available[0] > current[0]:
        return {'UpdateAvailable': True, 'UpdateType': 'Major'}
    elif available[1] > current[1] and available[0] == current[0] and update_dict[update_check_type] > 1:
        return {'UpdateAvailable': True, 'UpdateType': 'Minor'}
    elif available[2] > current[2] and available[0] == current[0] and available[1] == current[1] and update_dict[update_check_type] == 3:
        return {'UpdateAvailable': True, 'UpdateType': 'Build'}
    else:
        return {'UpdateAvailable': False, 'UpdateType': 'None'}

def return_property_as_list(input_list:list, property_name:str):
    return_list = []
    for item in input_list:
        return_list.append(item[property_name])
    return return_list

def return_slope(input_list_x:list, input_list_y:list):
    slope = ( ( len(input_list_y) * sum([a * b for a, b in zip(input_list_x, input_list_y)]) ) - ( sum(input_list_x) * sum(input_list_y)) ) / ( ( len(input_list_y) * sum([sq ** 2 for sq in input_list_x])) - (sum(input_list_x) ** 2))
    return slope

def get_current_version():

    try:
        with open(pathlib.Path(__file__).parent.parent / 'modules/version.json') as f:
            stat_version = json.loads(f.read())['FunctionVersion']
    except:
        stat_version = 'Unknown'

    return stat_version

def load_json_from_file(file_name:str):
    with open(pathlib.Path(__file__).parent.parent / f'files/{file_name}') as f:
        return json.loads(f.read())
    
def load_text_from_file(file_name:str, **kwargs):
    with open(pathlib.Path(__file__).parent.parent / f'files/{file_name}') as f:
        return f.read().format(**kwargs)

import pandas as pd

def list_to_html_table(input_list:list, max_rows=20, max_cols=10, nan_str='N/A', escape_html=True):
    '''Convert a list of dictionaries into an HTML table'''
    df = pd.DataFrame(input_list)
    df.index = df.index + 1
    html_table = df.to_html(max_rows=max_rows, max_cols=max_cols, na_rep=nan_str, escape=escape_html).replace('\n', '')

    return html_table

def update_column_value_in_list(input_list:list, col_name:str, update_str:str):
    '''Updates the value of a column in each dict in the list, to include the column value in your replacement use [col_value]'''
    updated_list = []
    for row in input_list:
        row[col_name] = update_str.replace('[col_value]', row[col_name])
        updated_list.append(row)

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

def join_lists(left_list, right_list, kind, left_key, right_key, fill_nan=0):
    '''Join 2 lists of objects using a key.  Supported join kinds left, right, outer, inner, cross'''
    left_df = pd.DataFrame(left_list)
    right_df = pd.DataFrame(right_list)
    join_data = left_df.merge(right=right_df, how=kind, left_on=left_key, right_on=right_key)
    join_data = join_data.fillna(fill_nan)

    return join_data.to_dict('records')

def sum_column_by_key(input_list, key):
    df = pd.DataFrame(input_list)
    return int(df[key].sum())

def max_column_by_key(input_list, key):
    df = pd.DataFrame(input_list)
    return int(df[key].max())

def sort_list_by_key(input_list, key, ascending=False):
    df = pd.DataFrame(input_list)
    df = df.sort_values(by=[key], ascending=ascending)
    return df.to_dict('records')

def coalesce(*args):
    for arg in args:
        if arg is not None:
            return arg
        
def version_check(current_version:str, avaialble_version:str, update_check_type:str):
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

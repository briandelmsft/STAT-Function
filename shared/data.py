import pandas as pd
import copy
import pathlib
import json
import os
from datetime import datetime, timezone
import re

date_format = os.getenv('DATE_FORMAT')
tz_info = os.getenv('TIME_ZONE')

def list_to_html_table(input_list:list, max_rows:int=20, max_cols:int=10, nan_str:str='N/A', escape_html:bool=True, columns:list=None, index:bool=False, justify:str='left', drop_empty_cols:bool=False):
    """Convert a list of dictionaries into an HTML table.
    
    This function takes a list of dictionaries and converts it to an HTML table format,
    with optional time zone and date formatting based on environment variables.
    
    Args:
        input_list (list): List of dictionaries to convert to HTML table.
        max_rows (int, optional): Maximum number of rows to display. Defaults to 20.
        max_cols (int, optional): Maximum number of columns to display. Defaults to 10.
        nan_str (str, optional): String to replace NaN values. Defaults to 'N/A'.
        escape_html (bool, optional): Whether to escape HTML characters. Defaults to True.
        columns (list, optional): Specific columns to include. Defaults to None.
        index (bool, optional): Whether to include row index. Defaults to False.
        justify (str, optional): Text alignment for table. Defaults to 'left'.
        drop_empty_cols (bool, optional): Whether to drop empty columns. Defaults to False.
    
    Returns:
        str: HTML table representation of the input data.
    """
    
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
    """Update column values in a list of dictionaries with templated strings.
    
    Updates the value of a specified column in each dictionary within the list.
    The update string can include [col_value] as a placeholder which will be 
    replaced with the current column value.
    
    Args:
        input_list (list): List of dictionaries to update.
        col_name (str): Name of the column to update.
        update_str (str): Template string for the new value. Use [col_value] 
            to reference the current column value.
    
    Returns:
        list: New list with updated dictionaries.
    """
    
    updated_list = []
    for row in input_list:
        current_row = copy.copy(row)
        current_row[col_name] = update_str.replace('[col_value]', current_row[col_name])
        updated_list.append(current_row)

    return updated_list

def replace_column_value_in_list(input_list:list, col_name:str, original_value:str, replacement_value:str):
    """Replace specific values in a column across a list of dictionaries.
    
    Updates the value of a specified column in each dictionary by replacing
    occurrences of the original value with the replacement value.
    
    Args:
        input_list (list): List of dictionaries to update.
        col_name (str): Name of the column to update.
        original_value (str): Value to be replaced.
        replacement_value (str): Value to replace with.
    
    Returns:
        list: New list with updated dictionaries.
    """
    
    updated_list = []
    for row in input_list:
        current_row = copy.copy(row)
        current_row[col_name] = current_row[col_name].replace(original_value, replacement_value)
        updated_list.append(current_row)

    return updated_list

def return_highest_value(input_list:list, key:str, order:list=['High','Medium','Low','Informational','None','Unknown']):
    """Find the highest value in a list of dictionaries.
    
    Searches through a list of dictionaries to find the highest value
    for a specific key, based on a predefined priority order.
    
    Args:
        input_list (list): List of dictionaries to search.
        key (str): Key name to check in each dictionary.
        order (list, optional): Priority order from highest to lowest. 
            Defaults to ['High','Medium','Low','Informational','None','Unknown'].
    
    Returns:
        str: The highest priority value found, or 'Unknown' if none match.
    """
    
    unsorted_list = []
    for item in input_list:
        unsorted_list.append(item[key].lower())

    for item in order:
        if item.lower() in unsorted_list:
            return item
    
    return 'Unknown'

def join_lists(left_list, right_list, kind, left_key, right_key, fill_nan=None):
    """Join two lists of dictionaries using specified keys and join kind.
    
    Args:
        left_list (list): List of dictionaries to join from the left.
        right_list (list): List of dictionaries to join from the right.
        kind (str): Type of join to perform ('left', 'right', 'outer', 'inner', 'cross').
        left_key (str): Key name in the left list to join on.
        right_key (str): Key name in the right list to join on.
        fill_nan (any, optional): Value to fill NaN entries in the result.
    
    Returns:
        list: List of dictionaries resulting from the join operation.
    """
    
    left_df = pd.DataFrame(left_list)
    right_df = pd.DataFrame(right_list)
    join_data = left_df.merge(right=right_df, how=kind, left_on=left_key, right_on=right_key)
    if fill_nan is None:
        join_data = join_data.where(join_data.notna(), None)
    else:
        join_data = join_data.fillna(fill_nan)

    return join_data.to_dict('records')

def sum_column_by_key(input_list, key):
    """Calculate the sum of a numeric column in a list of dictionaries.
    
    Args:
        input_list (list): List of dictionaries containing the data.
        key (str): Key name of the column to sum.
    
    Returns:
        int: Sum of the column values, or 0 if key doesn't exist.
    """
    
    df = pd.DataFrame(input_list)
    try:
        val = int(df[key].sum())
    except KeyError:
        val = int(0)
    return val

def max_column_by_key(input_list, key):
    """Find the maximum value in a numeric column of a list of dictionaries.
    
    Args:
        input_list (list): List of dictionaries containing the data.
        key (str): Key name of the column to find maximum value.
    
    Returns:
        int: Maximum value in the column, or 0 if key doesn't exist.
    """
    
    df = pd.DataFrame(input_list)
    try:
        val = int(df[key].max())
    except KeyError:
        val = int(0)
    return val

def min_column_by_key(input_list, key):
    """Find the minimum value in a numeric column of a list of dictionaries.
    
    Args:
        input_list (list): List of dictionaries containing the data.
        key (str): Key name of the column to find minimum value.
    
    Returns:
        int: Minimum value in the column, or 0 if key doesn't exist.
    """
    
    df = pd.DataFrame(input_list)
    try:
        val = int(df[key].min())
    except KeyError:
        val = int(0)
    return val

def sort_list_by_key(input_list, key, ascending=False, drop_columns:list=[]):
    """Sort a list of dictionaries by a specified key.
    
    Args:
        input_list (list): List of dictionaries to sort.
        key (str): Key name to sort by.
        ascending (bool, optional): Sort in ascending order. Defaults to False.
        drop_columns (list, optional): List of column names to drop from result. Defaults to [].
    
    Returns:
        list: Sorted list of dictionaries.
    """
    
    df = pd.DataFrame(input_list)
    df = df.sort_values(by=[key], ascending=ascending)
    if drop_columns:
        df.drop(columns=drop_columns, inplace=True)
    return df.to_dict('records')

def coalesce(*args):
    """Return the first non-None argument.
    
    Similar to SQL COALESCE function, returns the first argument that is not None.
    
    Args:
        *args: Variable number of arguments to check.
    
    Returns:
        Any: The first non-None argument, or None if all arguments are None.
    """
    
    for arg in args:
        if arg is not None:
            return arg
        
def version_check(current_version:str, avaialble_version:str, update_check_type:str):
    """Check if an update is available based on version comparison.
    
    Compares current version with available version to determine if an update
    is available based on the specified update check type.
    
    Args:
        current_version (str): Current version string in format "major.minor.build".
        avaialble_version (str): Available version string in format "major.minor.build".
        update_check_type (str): Type of update to check for ('Major', 'Minor', or 'Build').
    
    Returns:
        dict: Dictionary with 'UpdateAvailable' (bool) and 'UpdateType' (str) keys.
    """

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
    """Returns a list of property data from a list of dictionaries.
    
    From a list of dicstionaries, extracts the values of a specified property
    and returns them as a list.
    
    Args:
        input_list (list): List of dictionaries to extract property from.
        property_name (str): Name of the property to extract from each dictionary.
    
    Returns:
        list: List of values for the specified property from each dictionary.
    """

    return_list = []
    for item in input_list:
        return_list.append(item[property_name])
    return return_list

def return_slope(input_list_x:list, input_list_y:list):
    """Calculate the slope of a linear regression line for two lists of values.
    
    Args:
        input_list_x (list): List of x-values.
        input_list_y (list): List of y-values.
    
    Returns:
        float: Slope of the linear regression line calculated from the two lists.
    """

    slope = ( ( len(input_list_y) * sum([a * b for a, b in zip(input_list_x, input_list_y)]) ) - ( sum(input_list_x) * sum(input_list_y)) ) / ( ( len(input_list_y) * sum([sq ** 2 for sq in input_list_x])) - (sum(input_list_x) ** 2))
    return slope

def get_current_version():
    """Get the current STAT Function version from version.json file.
    
    Reads the version information from the modules/version.json file.
    
    Returns:
        str: Current function version string, or 'Unknown' if unable to read.
    """

    try:
        with open(pathlib.Path(__file__).parent.parent / 'modules/version.json') as f:
            stat_version = json.loads(f.read())['FunctionVersion']
    except:
        stat_version = 'Unknown'

    return stat_version

def load_json_from_file(file_name:str):
    """Load and parse JSON data from a file in the modules/files directory.
    
    Args:
        file_name (str): Name of the JSON file to load.
    
    Returns:
        dict: Parsed JSON data from the file.
    """

    with open(pathlib.Path(__file__).parent.parent / f'modules/files/{file_name}') as f:
        return json.loads(f.read())
    
def load_text_from_file(file_name:str, **kwargs):
    """Load text from a file and format it with provided keyword arguments.
    
    Args:
        file_name (str): Name of the text file to load from modules/files directory.
        **kwargs: Keyword arguments to use for string formatting.
    
    Returns:
        str: Formatted text content from the file.
    """

    with open(pathlib.Path(__file__).parent.parent / f'modules/files/{file_name}') as f:
        return f.read().format(**kwargs)

def list_to_string(list_in:list, delimiter:str=', ', empty_str:str='N/A'):
    """Convert a list to a delimited string.
    
    Args:
        list_in (list): List to convert to string.
        delimiter (str, optional): Delimiter to use between items. Defaults to ', '.
        empty_str (str, optional): String to return if list is empty. Defaults to 'N/A'.
    
    Returns:
        str: Delimited string representation of the list, or empty_str if list is empty.
    """

    if not list_in:
        return empty_str
        
    if isinstance(list_in, list):
        try:
            return delimiter.join(list_in)
        except:
            return list_in
    else:
        return list_in
    
def parse_kv_string(kv:str, item_delimitter:str=';', value_delimitter:str='='):
    """Parse a string of key-value pairs into a dictionary.
    
    Args:
        kv (str): The string containing key-value pairs to parse.
        item_delimitter (str, optional): Delimiter between items. Defaults to ';'.
        value_delimitter (str, optional): Delimiter between key and value. Defaults to '='.
    
    Returns:
        dict: Dictionary of parsed key-value pairs. Values are None if no delimiter found.
    """

    kv_pairs = kv.split(item_delimitter)
    result = {}
    for pair in kv_pairs:
        if value_delimitter in pair:
            key, value = pair.split(value_delimitter, 1)
            result[key.strip()] = value.strip()
        else:
            result[pair.strip()] = None
    return result

def convert_from_iso_format(date_string):
    """Convert an ISO 8601 date string to a datetime object and assume UTC if not time zone is provided.

    Args:
        date_string (str): The ISO 8601 date string to convert.
        
    Returns:
        datetime: A datetime object representing the date and time with time zone information.
    """

    ts = datetime.fromisoformat(date_string)

    if ts.tzinfo is not None and ts.tzinfo.utcoffset(ts) is not None:
        return ts
    else:
        return ts.replace(tzinfo=timezone.utc)   

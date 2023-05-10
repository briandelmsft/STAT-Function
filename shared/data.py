import pandas as pd

def list_to_html_table(input_list:list, max_rows=20, max_cols=10, nan_str='N/A'):
    '''Convert a list of dictionaries into an HTML table'''
    df = pd.DataFrame(input_list)
    df.index = df.index + 1
    html_table = df.to_html(max_rows=max_rows, max_cols=max_cols, na_rep=nan_str).replace('\n', '')

    return html_table

def return_highest_value(input_list:list, key:str, order:list=['High','Medium','Low','Informational','Unknown']):
    '''Locate the highest value in a list of dictionaries by key'''
    
    unsorted_list = []
    for item in input_list:
        unsorted_list.append(item[key].lower())

    for item in order:
        if item.lower() in unsorted_list:
            return item
    
    return 'Unknown'

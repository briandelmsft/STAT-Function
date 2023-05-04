import pandas as pd

def list_to_html_table(list, max_rows=20, max_cols=10):
    df = pd.DataFrame(list)
    df.index = df.index + 1
    html_table = df.to_html(max_rows=max_rows, max_cols=max_cols).replace('\n', '')

    return html_table
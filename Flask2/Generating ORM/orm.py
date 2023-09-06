import pandas as pd

datafile = 'F:\Python\Excel_Project\Data_Files\ARC-ng.xlsx'
df = pd.read_excel(datafile, sheet_name='ARC_PERSONS')

try:
    # Extract table information
    table_name = 'ARC_PERSONS'
    columns = df['Column Name'].lower()
    data_types = df['Data Type (SQLite)']
    primary_key = df['Primary Key'].apply(lambda x: True if x == 'Yes' else False)
    foreign_keys = df['Foreign Key'].apply(lambda x: True if x == 'Yes' else False)

    # Generate Python script
    python_script = f"""class {table_name.capitalize()}(db.Model):\n"""

    # Generate column definitions
    for column, dt_SQLite, is_primary, is_foreign in zip(columns, data_types, primary_key, foreign_keys):
        column_definition = f"    {column} = db.Column(db.{dt_SQLite}"
        if is_primary:
            column_definition += ", primary_key=True"
        column_definition += ")"
        python_script += column_definition + '\n'

    python_script += f"""
    def json(self):
        return {{
            {', '.join([f"'{column}': self.{column}" for column in columns])}
        }}
"""

    # Write Python script to a file
    outputfile = 'F:\\Python\\Excel_Project\\Data_Files\\arc_persons_orm.py'
    with open(outputfile, 'w') as file:
        file.write(python_script)

except KeyError as e:
    print(f"Error: Column '{e.args[0]}' not found in the Excel sheet. Please check the column names.")

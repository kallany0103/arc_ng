import pandas as pd

datafile = 'F:\Python\Excel_Project\Data_Files\HR.xlsx'
df = pd.read_excel(datafile, sheet_name='Employees')
df1 = df[['EMPLOYEE_ID', 'FIRST_NAME', 'LAST_NAME', 'SALARY']]
v_employee_id = 101
data = df1[df1['EMPLOYEE_ID'] == v_employee_id].to_dict(orient='records')
print(data)

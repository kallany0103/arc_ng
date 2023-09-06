from flask import Flask, jsonify, request
import pandas as pd

datafile = 'F:\Python\Excel_Project\Data_Files\HR.xlsx'
df = pd.read_excel(datafile, sheet_name='Employees')
df1 = df[['EMPLOYEE_ID', 'FIRST_NAME', 'LAST_NAME', 'SALARY', 'DEPARTMENT_ID']]

app = Flask(__name__)

@app.route('/employees')
def get_datas():
    data = df1.to_dict(orient='records')
    return jsonify(data)

@app.route('/employees/filter')
def get_data():
    EMPLOYEE_ID = request.args.get('EMPLOYEE_ID')
    DEPARTMENT_ID = request.args.get('DEPARTMENT_ID')
    #EMPLOYEE_ID = int(EMPLOYEE_ID) #needs to convert the parameter(EMPLOYEE_ID) into integer value
    filtered_data = df1[(df1['EMPLOYEE_ID'] == int(EMPLOYEE_ID)) & (df1['DEPARTMENT_ID'] == int(DEPARTMENT_ID))]
    data = filtered_data.to_dict(orient = 'records')
    print(EMPLOYEE_ID)
    if data:
        return jsonify(data[0])
    else:
        return jsonify({'Message': 'Record not Found'})

if __name__ == '__main__':
    app.run()


#http://127.0.0.1:5000/employees/filter?EMPLOYEE_ID=100&DEPARTMENT_ID=90

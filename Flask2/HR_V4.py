from flask import Flask, jsonify, request
import pandas as pd

datafile = 'F:/Python/Excel_Project/Data_Files/HR.xlsx'
df = pd.read_excel(datafile, sheet_name='Employees')
df1 = df[['EMPLOYEE_ID', 'FIRST_NAME', 'LAST_NAME', 'SALARY', 'MANAGER_ID', 'DEPARTMENT_ID']]

app = Flask(__name__)

@app.route('/employees')
def get_datas():
    data = df1.to_dict(orient='records')
    return jsonify(data)

@app.route('/employees/filter')
def get_data():
    MANAGER_ID = request.args.get('MANAGER_ID')
    DEPARTMENT_ID = request.args.get('DEPARTMENT_ID')

    if MANAGER_ID is None and DEPARTMENT_ID is None:
        return jsonify({'Message': 'At least one parameter is required.'})

    filtered_data = df1
    if MANAGER_ID:
        filtered_data = filtered_data[filtered_data['MANAGER_ID'] == int(MANAGER_ID)]
    if DEPARTMENT_ID:
        filtered_data = filtered_data[filtered_data['DEPARTMENT_ID'] == int(DEPARTMENT_ID)]

    data = filtered_data.to_dict(orient='records')

    if data:
        return jsonify(data)
    else:
        return jsonify({'Message': 'Record not Found'})

if __name__ == '__main__':
    app.run()

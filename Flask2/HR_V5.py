from flask import Flask, jsonify, request
import openpyxl

datafile = 'F:\Python\Excel_Project\Data_Files\HR.xlsx'
sheet_name = 'Employees'

def read_data_from_excel():
    book = openpyxl.load_workbook(datafile)
    sheet = book[sheet_name]
    data = []

    for row in sheet.iter_rows(min_row=2, values_only=True):
        # Assuming the column order: EMPLOYEE_ID, FIRST_NAME, LAST_NAME, SALARY, DEPARTMENT_ID
        data.append({
            'EMPLOYEE_ID': row[0],
            'FIRST_NAME': row[1],
            'LAST_NAME': row[2],
            'SALARY': row[3],
            'DEPARTMENT_ID': row[4]
        })

    return data

app = Flask(__name__)

@app.route('/employees')
def get_datas():
    data = read_data_from_excel()
    return jsonify(data)

@app.route('/employees/filter')
def get_data():
    EMPLOYEE_ID = request.args.get('EMPLOYEE_ID')
    DEPARTMENT_ID = request.args.get('DEPARTMENT_ID')
    # Convert to integer values
    EMPLOYEE_ID = int(EMPLOYEE_ID) if EMPLOYEE_ID else None
    DEPARTMENT_ID = int(DEPARTMENT_ID) if DEPARTMENT_ID else None

    data = read_data_from_excel()
    filtered_data = [item for item in data if (EMPLOYEE_ID is None or item['EMPLOYEE_ID'] == EMPLOYEE_ID) and
                                               (DEPARTMENT_ID is None or item['DEPARTMENT_ID'] == DEPARTMENT_ID)]

    if filtered_data:
        return jsonify(filtered_data[0])
    else:
        return jsonify({'Message': 'Record not Found'})

if __name__ == '__main__':
    app.run()

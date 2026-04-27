import requests

URL = "https://capital-0x50f4h9.alfactf.ru/api/applications"

payload = {
  "application_name": "winner", 
  "last_name": "Цтфный",
  "first_name": "Лев",
  "patronymic": "Альфабанкович", 
  "birth_date": "1994-04-25",
  "annual_income": 1000000,
  "amount": 1000000,
  "term_months": 52,
  "monthly_expenses": 75000,
  "employer": "Karabin Capital",
  "housing_type": "Office apartment",
  "occupation_type": "Accountants", 
  "education_type": "Higher education",
  "family_status": "Married",
  "karabin_payroll_project": 1
}

r = requests.post(URL, json=payload)
print(r.json())

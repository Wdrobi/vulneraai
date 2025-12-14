from selenium import webdriver
import time
from selenium.webdriver.common.by import By

driver = webdriver.Chrome()  
driver.get("https://studentportal.green.edu.bd/")

input_x = driver.find_element(By.ID,"Input_LoginId")
input_x.send_keys("222002068")

input_y = driver.find_element(By.ID,"Input_Password")
input_y.send_keys("Robiul@robi009")
input_y.submit()

time.sleep(50)
driver.quit()
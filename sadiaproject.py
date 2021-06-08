import streamlit as st
import pandas as pd
import sqlite3
import hashlib
from PIL import Image


# Security
# passlib,hashlib,bcrypt,scrypt


def make_hashes(password):
    return hashlib.sha256(str.encode(password)).hexdigest()


def check_hashes(password, hashed_text):
    if make_hashes(password) == hashed_text:
        return hashed_text
    return False


# DB Management


conn = sqlite3.connect('data.db')
c = conn.cursor()


# DB  Functions
def create_users_table():
    c.execute('CREATE TABLE IF NOT EXISTS users_table(username VARCHAR,password VARCHAR)')


def add_userdata(username, password):
    c.execute('INSERT INTO users_table(username,password) VALUES (?,?)', (username, password))
    conn.commit()


def login_user(username, password):
    c.execute('SELECT * FROM users_table WHERE username =? AND password = ?', (username, password))
    data = c.fetchall()
    return data


def view_all_users():
    c.execute('SELECT * FROM users_table')
    data = c.fetchall()
    return data


def view_user_record():
    c.execute('SELECT DISTINCT username FROM users_table')
    data = c.fetchall()
    return data


def main():
    """MD5 Hash Checksum App"""

    st.title("Application of checksum App")

    menu = ["Home", "Login", "SignUp", "Admin"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Home":
        st.subheader("MD5 Hashes: ")
        st.write("The MD5 hashing algorithm is a one-way cryptographic function that accepts a message of any length "
                 "as input and returns as output a fixed-length digest value to be used for authenticating the "
                 "original message.The MD5 hash function was originally designed for use as a secure cryptographic "
                 "hash algorithm for authenticating digital signatures. MD5 has been deprecated for uses other than "
                 "as a non-cryptographic checksum to verify data integrity and detect unintentional data corruption. "
                 "Although originally designed as a cryptographic message authentication code algorithm for use on "
                 "the internet, MD5 hashing is no longer considered reliable for use as a cryptographic checksum "
                 "because researchers have demonstrated techniques capable of easily generating MD5 collisions on "
                 "commercial off-the-shelf computers. Ronald Rivest, founder of RSA Data Security and institute "
                 "professor at MIT, designed MD5 as an improvement to a prior message digest algorithm, "
                 "MD4. ")
        image = Image.open('pic1.jpg')
        st.image(image, width=700)
        st.write("Describing it in Internet Engineering Task Force RFC 1321, 'The MD5 Message-Digest Algorithm,"
                 "' he wrote: "
                 "The algorithm takes as input a message of arbitrary length and produces as output a 128-bit "
                 "'fingerprint' or 'message digest' of the input. It is conjectured that it is computationally "
                 "infeasible to produce two messages having the same message digest, or to produce any message having "
                 "a given pre-specified target message digest. The MD5 algorithm is intended for digital signature "
                 "applications, where a large file must be 'compressed' in a secure manner before being encrypted "
                 "with a private (secret) key under a public-key cryptosystem such as RSA. "
                 "The IETF suggests MD5 hashing can still be used for integrity protection, noting Where the MD5 "
                 "checksum is used inline with the protocol solely to protect against errors, an MD5 checksum is "
                 "still an acceptable use.' However, it  added that 'any application and protocol that employs MD5 "
                 "for any purpose needs to clearly state the expected security services from their use of MD5.")
        image = Image.open('pic2.jpeg')
        st.image(image, width=650)


    elif choice == "Login":
        st.subheader("Login Section")
        username = st.sidebar.text_input("UserName")
        password = st.sidebar.text_input("Password", type='password')
        if st.sidebar.checkbox("Login"):
            # if password == '12345':
            create_users_table()
            hashed_pswd = make_hashes(password)

            result = login_user(username, check_hashes(password, hashed_pswd))
            if result:

                st.success("Logged In as {}".format(username))
                string = st.text_input("Write Text : ")
                # encoding the string using encode()
                en = string.encode()
                # passing the encoded string to MD5
                hex_result = hashlib.md5(en)
                # printing the equivalent hexadecimal value
                image = Image.open('pic3.jpeg')
                st.image(image, width=600)

                st.write("The hexadecimal equivalent of hash is : ")
                st.info(hex_result.hexdigest())

            else:
                st.warning("Incorrect Username/Password")





    elif choice == "SignUp":
        st.subheader("Create New Account")
        new_user = st.text_input("Username")
        new_password = st.text_input("Password", type='password')

        if st.button("Signup"):
            create_users_table()
            add_userdata(new_user, make_hashes(new_password))
            st.success("You have successfully created a valid Account")
            st.info("Go to Login Menu to login")

    elif choice == "Admin":
        st.subheader("Welcome")

        def authenticate(username, password):
            return username == "admin123" and password == "admin456"

        username = st.text_input('Admin_Name')
        password = st.text_input("password", type='password')
        if st.checkbox("Login"):
            if authenticate(username, password):
                st.success('You are Successfully Login as Admin !')
                task = st.selectbox("Task", ["Select option", "Profiles"])
                if task == "Profiles":
                    st.subheader("Users Profiles")
                    user_result = view_user_record()
                    clean_db = pd.DataFrame(user_result,
                                            columns=["Username"])
                    st.dataframe(clean_db)
            else:
                st.error('The username or password you have entered is invalid.')


if __name__ == '__main__':
    main()

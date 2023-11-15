from tkinter import *
from tkinter import messagebox
import base64


def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def save_encryptNotes():
    notes_title = title_entry.get()
    message = enter_text.get('1.0', END)
    master_secret = secretKey_Entry.get()
    if len(notes_title) == 0 or len(message) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title='HATA', message="Lütfen Tüm Bilgileri Giriniz")
    else:
        # encryption
        message_encrypted = encode(master_secret, message)
        try:
            with open("Gizlenen_Notlar.txt", "a",encoding="utf-8") as data:
                data.write(f"\n{notes_title}\n{message_encrypted}")
        except FileNotFoundError:
            with open("Gizlenen_Notlar.txt", "W",encoding="utf-8") as data:
                data.write(f"\n{notes_title}\n{message_encrypted}")
        finally:
            title_entry.delete(0, END)
            secretKey_Entry.delete(0, END)
            enter_text.delete("1.0", END)


def decrypt_notes():
    text_encrypted = enter_text.get('1.0', END)
    master_key = secretKey_Entry.get()
    if len(text_encrypted) == 0 or len(master_key) == 0:
        messagebox.showinfo(title="HATA", message="Lütfen Bütün Bilgileri Giriniz!")
    else:
        try:
            message_decrypt = decode(master_key, text_encrypted)
            enter_text.delete("1.0", END)
            enter_text.insert("1.0", message_decrypt)
        except:
            messagebox.showinfo(title="Hata!", message="Please enter encypted text!")


window = Tk()
window.title("Gizli Notlarım")
window.config(padx=30, pady=30)

icon = PhotoImage(file="9136265.png")
iconLabel = Label(image=icon)
iconLabel.pack()

info_title = Label(text="Notunuzun Başlığını Giriniz", font=("arial", 20, "normal"))
info_title.pack()
title_entry = Entry()
title_entry.pack()
input_label = Label(text="Gizlenecek Notunuzu Yazınız!", font=("arial", 20, "bold"))
input_label.pack()
enter_text = Text(width=50, height=15)
enter_text.pack()
secretKey_label = Label(text="Gizlenecek Notunuz İçin Bir Parola Bellirleyiniz!", font=("arial", 20, "bold"))
secretKey_label.pack()
secretKey_Entry = Entry(width=20)
secretKey_Entry.pack()

save_button = Button(text="Kaydet ve Şifrele ", command=save_encryptNotes)
save_button.pack()

button_decrypt = Button(text="Notun şifresini \nÇözümle", command=decrypt_notes)
button_decrypt.pack()

window.mainloop()

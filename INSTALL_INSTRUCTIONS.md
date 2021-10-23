# Install instructions and configuration

## Programs to download (for Windows)
* Download and Install 7zip: https://www.7-zip.org/
* Download and Install JDK 17 from Oracle: https://www.oracle.com/java/technologies/downloads/ Note that I use [JDK 16](https://drive.google.com/file/d/1V_H7V7W8oyzmuHQ3I7pBaFf1ZvHKufkZ/view?usp=sharing).
* Download and Install [JDK 8](https://www.oracle.com/java/technologies/javase/javase-jdk8-downloads.html#license-lightbox) if you want you can download the file from my personal archive here: https://drive.google.com/file/d/1F_rzI8d-8FIbVgEz19wCw6o1lbDjjwzD/view?usp=sharing
* Download and Install Android Studio from here: https://developer.android.com/studio/
* For Android Studio download the SDK, API Level 26 and 29. You can help yourself with this article: https://developer.android.com/studio/intro/update#sdk-manager 

### Optionals downloads for personal experiments
* If you want you can download the original EU zip project from [here](https://github.com/jojo2234/GreenPassHack/blob/main/dgca-app-core-android-main.zip), if you download it from the original repository be aware of the version because MykhailoNester has updated it, I don't know if it's related to the email I've sent to him. However, to avoid problems with versions, I have uploaded the old ones that I own.
* You can download a python interpreter to execute the old code from the orginal [README](https://github.com/jojo2234/GreenPass-Experiments/blob/main/README_BKP.md) if you are interested. You can download and install Python from https://www.python.org/downloads/
* Download and install a good text editor like VS Code https://code.visualstudio.com/ to run python scripts or to easy modify Kotlin scripts.

## Instruction to execute GettingUp.kt

* Start Android Studio
* Let Android Studio make all the available updates
* If appear some pop-up to install Kotlin plugins or other extension do it
* Reboot your PC only when Android Studio has ended everything
* Download and decompress with 7zip this zipped directory: [VerificaC19_SRC.7z](https://github.com/jojo2234/GreenPass-Experiments/blob/main/VerificaC19_SRC.7z)
* Be sure your PC is connected to Internet (so it will upload the Grandle file and download dependecies)
* Start Android Studio and open the project inside the folder VerificaC19 called dgca-app-core-android-main
* To open the project from Android Studio click on Open button in the first Window that appear or from the File Menu open a project, then inside the folder VerificaC19_SRC select dgca-app-core-android-main and press the OK button.
* Android Studio will start to download some stuff let do it what it want to do until the project is completely loaded, check the progress bar status (bottom-right).
* When the project is opened you can use the menu on the left inside Android Studio to browse the folder. The GettingUp.kt file is in decoder>src>main>java>dgca>verifier>app>decoder search the file and make double click and it will be opened on the right panel.
* You can open the file and scroll down until you see the main function and than compile it pressing the green play button near the header of the function. That is imporant, to make the script run you should use the play button near the header of the function the first time that you will execute it.

## FAQ

### I don't see the green play button

Try to move the mouse where the line numbers are located, near the header of the main function.

### The play button is gray or doesn't appear

Most probably is due to a missing dependence, try to go in panel at the bottom of Android Studio in Sync and look for the warning reported under build.grandle.
You should see a blue link among the red words on the right panel that says: "Install missing SDK packages". Do it and everything should work well. When you change something be patient.
If it's not your problem watch this for grandle version error: https://stackoverflow.com/questions/22148584/android-studio-gradle-sync-project-failed

### I don't see the panel at the bottom with Sync
Open GettingUp.kt and in the top yellow bar that appear reporting the grandle error click on "Try Again", than the bottom panel should appear.

### I got other errors
Try to open the other projects in the folder and let Android Studio download what it need.
Close the project and open it again.
It's important be patient.

### Println and readline are unknown references

<b>In any case before do the thing written below, try to run the project.</b>

In Android Studio open the window Project Structure in the File menu.

On the menu item called Modules:
* Switch compile SDK version to 29
* Source compatibility to 1.8
* Target compatibility to 1.8

Apply, then ok and wait.

If what written above doesn't work.

You could try to substitute all println to System.out.println("")
or you can check if you have installed Intellij close Android Studio, open Intellij and clear the cache
Otherwise close Android Studio and erase the folder .AndroidStudio in AppData
Than open Android Studio again.

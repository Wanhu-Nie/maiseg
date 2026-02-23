# **MaISeg: Malware Classification via Image Segmentation**



## **📖 Overview**

**MaISeg** is a novel and effective malware visualization classification framework that leverages the principles of image segmentation to convert binary executable files (PEs) into RGB feature maps. Unlike traditional grayscale mapping methods, MaISeg explicitly distinguishes sections as natural byte/semantic boundaries and incorporates the calculation of in-block contextual feature values to take into account both global structure and local features. Experimental results demonstrate that MaISeg exhibits outstanding performance comparable to state-of-the-art methods across various aspects, including benchmark PE malware datasets (Malimg, BIG-2015, and MOTIF), cross-platform compatibility (CICMalDrodi2020, Android), and adversarial robustness testing.



## **🚀 Features**

| Feature                           | Description                                              |
| :-------------------------------- | :------------------------------------------------------- |
| **Adaptive Length Handling**      | Dynamically adjusts to malware of varying sizes          |
| **Color Encoding**                | RGB channel encoding for richer feature representation   |
| **Section Boundary Preservation** | Maintains structural information from executable headers |
| **Adversarial Robustness**        | Resistant to section reordering and manipulation attacks |
| **Multi-Dataset Support**         | Compatible with Malimg, BIG-2015, MOTIF, CICMalDroid2020 |



## **📊 Performance Highlights**

| Dataset                       | Classes | Samples | Accuracy                        |
| :---------------------------- | :------ | :------ | :------------------------------ |
| **Malimg**                    | 25      | 9,339   | 99.88%                          |
| **BIG-2015**                  | 9       | 10,868  | 99.49%                          |
| **MOTIF**                     | 454     | 3,095   | top 50: 82.27%; top 100: 79.22% |
| **CICMalDroid2020** (Android) | 4       | 13,202  | 94.19%                          |




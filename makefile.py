import os
import cv2
import pefile
from PIL import Image
import numpy as np
import pandas as pd
from pandarallel import pandarallel
from math import ceil

''' 默认MaISeg策略采用fair, orig/log2可选 '''
strategy = 'fair'

''' 输入/输出文件目录, 全局变量 '''
binary_dir = ''
output_image_dir = ''

''' 输出图像分辨率默认为224*224 '''
wh = 224
blocks = 224**2

''' 熵计算 '''
def entropy(seq, base=2):
    _, counts = np.unique(seq, return_counts=True)
    probs = counts / len(seq)
    # 过滤掉概率为0的项（虽然unique不会产生0，但安全起见）
    probs = probs[probs > 0]
    entropy = -np.sum(probs * np.log(probs)) / np.log(base)
    return entropy

def section_distribution_remapping():
    ''' 为简单起见, SDR策略被集成于LAFC算法中实现 '''
    pass

def local_adaptive_feature_compression(binary_bytes, item):
    ''' LAFC算法实现. 为简单实现, 将SDR(section distribution remapping)进行集成 '''

    if strategy == 'fair':
        if item['section_table_parsing']:
            ''' 节表无效, 需要手动解析 '''
            # 无效节填充
            expend = 0xcc

            ''' 校验section信息完整性 '''
            section = item['section'][0]
            section_keys = list(section.keys())
            # 当前文件偏移指针
            cur_ptr = int(item['imagebase'], 16)
            if 'HEADER' not in section.keys() and int(section[section_keys[0]]['ip'], 16) != 0:
                section = {'HEADER':{'ip':hex(int(section[section_keys[0]]['ip'], 16)-0x1000), 'size':'0x1000'}} | section
                section_keys = list(section.keys())
                header_ip = int(section['HEADER']['ip'], 16)
                assert cur_ptr == header_ip, 'repair header error!'
                cur_ptr = header_ip

            for key, value in section.items():
                assert int(value['ip'], 16) == cur_ptr, 'section offset error!'
                cur_ptr += int(value['size'], 16)

            ''' 分割section的bytes '''
            seq ={}

            if len(section_keys) > 1:
                # 处理HEADER
                if item['file_base'] == int(section[section_keys[1]]['ip'], 16):
                    # bytes缺少header(0x1000)
                    seq['HEADER'] = [expend] * 0x1000
                    cur_ptr = 0
                elif item['file_base'] == int(section[section_keys[0]]['ip'], 16) + 0x1000:
                    # pe.header > 0x1000, bytes舍去前0x10000个字节
                    cur_ptr = int(section[section_keys[0]]['size'], 16) - 0x1000
                    seq['HEADER'] = [expend] * 0x1000 + binary_bytes[:cur_ptr]
                elif item['file_base'] == int(section[section_keys[0]]['ip'], 16):
                    # bytes包含完整pe
                    cur_ptr = int(section[section_keys[0]]['size'], 16)
                    seq['HEADER'] = binary_bytes[:cur_ptr]
                else:
                    # header
                    print(f'{item["file"]} -> segment bytes header error!')
                    raise ValueError("无效的输入值")
                section.pop('HEADER')

                for key, value in section.items():
                    section_size = int(value['size'],16)
                    seq[key] = binary_bytes[cur_ptr:cur_ptr+section_size]
                    cur_ptr += section_size

                    assert len(seq[key]) == section_size, f'{item["file"]} -> segment bytes error!'
            else:
                seq[section_keys[0]] = [expend] * 0x1000 + binary_bytes

        else:
            ''' 利用pefile解析节表 '''
            pe = pefile.PE(data=bytes(binary_bytes))
            sections = pe.sections
            if pe.FILE_HEADER.NumberOfSections != len(sections):
                raise 'Error!'

            # HEADER
            PointerToRawData = len(pe.header)
            seq = {'HEADER':binary_bytes[:PointerToRawData]}

            # sections
            for section in pe.sections:
                try:
                    section_name = section.Name.rstrip(b'\x00').decode('ascii')
                    if section.PointerToRawData:
                        assert PointerToRawData == section.PointerToRawData, f'Error! {item[2]}'
                except:
                    section_name = section.Name

                if section.SizeOfRawData:
                    seq[section_name] = binary_bytes[PointerToRawData:PointerToRawData+section.SizeOfRawData]
                    PointerToRawData += section.SizeOfRawData
                else:
                    ''' bss等未初始化的空节 '''
                    seq[section_name] = [0xcc for _ in range(512)]

                ''' 部分节的节表信息错误, 可能导致空节的出现!!! '''
                if not len(seq[section_name]):
                    # print(f'{sample} 表信息错误!')
                    seq[section_name] = [0xcc for _ in range(512)]

        ''' 删除节中的无效0填充 '''
        for key, value in seq.items():
            index = len(value) - 1
            while index > 0 and value[index] == 0:
                index -= 1
            
            if index > 0:
                seq[key] = value[:index+1]
            else:
                seq[key] = [expend] * min(len(value), 512)

        ''' SDR策略 '''
        n_map = {}
        n = wh**2 // len(seq)
        for key in seq.keys():
            n_map[key] = n
            
        local_feature_descriptor_sets = {'r':[], 'g':[], 'b':[]}
        for key, value, n in zip(seq.keys(), seq.values(), n_map.values()):
            l = ceil(len(value) / n)
            value += [0 for _ in range(l * n - len(value))]

            for index in range(n):
                cur = index * l
                byte_fragment = value[cur:cur+l]

                byte_fragment_mean = np.mean(byte_fragment)
                byte_fragment_std = np.std(byte_fragment, ddof=1) if len(byte_fragment) >= 2 else 0
                byte_fragment_entropy = entropy(byte_fragment)

                local_feature_descriptor_sets['r'].append(byte_fragment_mean)
                local_feature_descriptor_sets['g'].append(byte_fragment_std)
                local_feature_descriptor_sets['b'].append(byte_fragment_entropy)

    elif strategy == 'orig':
        l = ceil(len(binary_bytes) / blocks)
        binary_bytes += [0 for _ in range(l * blocks - len(binary_bytes))]  
        assert not len(binary_bytes) % (blocks), "Error: binary_bytes is not aligned!"

        ''' 在块内上下文计算局部特征描述符 '''
        local_feature_descriptor_sets = {'r':[], 'g':[], 'b':[]}
        for block_index in range(blocks):
            cur = block_index * l
            byte_fragment = binary_bytes[cur:cur+l]
            
            byte_fragment_mean = np.mean(byte_fragment)
            byte_fragment_std = np.std(byte_fragment, ddof=1) if len(byte_fragment) >= 2 else 0
            byte_fragment_entropy = entropy(byte_fragment)

            local_feature_descriptor_sets['r'].append(byte_fragment_mean)
            local_feature_descriptor_sets['g'].append(byte_fragment_std)
            local_feature_descriptor_sets['b'].append(byte_fragment_entropy)

    else:
        raise ValueError(f"Error: Invalid strategy: {strategy}")

    return local_feature_descriptor_sets


def to_image(sets, image_path):
    ''' 将特征描述符集合存储为RGB特征图 '''

    def min_max_scaling(matrix, feature_range=(0, 1)):
        min_val = np.min(matrix)
        max_val = np.max(matrix)

        if min_val == max_val:
            return np.zeros(shape=matrix.shape)

        # 计算缩放后的范围
        new_min, new_max = feature_range
        # 进行 Min - Max 缩放
        scaled_matrix = (matrix - min_val) / (max_val - min_val) * (new_max - new_min) + new_min
        return scaled_matrix

    ''' 填充剩余空间 '''
    sets['r'] += [0 for _ in range(blocks - len(sets['r']))]
    sets['g'] += [0 for _ in range(blocks - len(sets['g']))]
    sets['b'] += [0 for _ in range(blocks - len(sets['b']))]
    assert len(sets['r']) == blocks, "图像转换错误!"
    assert len(sets['g']) == blocks, "图像转换错误!"
    assert len(sets['b']) == blocks, "图像转换错误!"

    img_r = Image.fromarray(np.uint8(sets['r']).reshape(wh, wh))
    img_g = Image.fromarray(np.uint8(sets['g']).reshape(wh, wh))
    img_b = Image.fromarray(np.uint8(min_max_scaling(np.array(sets['b']), feature_range=(0,255))).reshape(wh, wh))
    Image.merge("RGB", (img_r, img_g, img_b)).save(image_path)

def big2015_item_processing(item):
    ''' BIG-2015数据集中的二进制文件存储在".bytes"文件中, 每行起始标记虚拟地址, 需要忽略 '''
    file = os.path.join(binary_dir, item['file'] + '.bytes')
    item['section_table_parsing'] = True

    ''' 读取二进制字节 '''
    with open(file, mode='r') as bytes:
        # 记录bytes文件的首地址ip
        item['file_base'] = int(bytes.readline().split(' ')[0], 16)
        bytes.seek(0)

        binary_bytes = []
        for bytes_line in bytes.readlines():
            bytes_line = bytes_line.replace('\n', '').split(' ')[1:]
            for byte in bytes_line:
                binary_bytes += [int(byte, 16) if byte != '??' else 0]
    
    ''' LAFC + SDR '''
    local_feature_descriptor_sets = local_adaptive_feature_compression(binary_bytes, item)
    
    ''' RGB特征图存储 '''
    image_path = os.path.join(output_image_dir, item['id'], item['file']+'.png') 
    to_image(local_feature_descriptor_sets, image_path)

def malimg_item_processing(item):
    ''' Malimg数据集中的样本为原始图像(2D bytes), 需要提取转换为一维 '''
    file = item[0]
    family, sample = os.path.split(file)
    family = os.path.basename(family)

    ''' 读取二进制字节 '''
    binary_bytes = list(cv2.imread(file, cv2.IMREAD_GRAYSCALE).reshape(1,-1)[0])

    ''' LAFC + SDR '''
    item['section_table_parsing'] = False
    local_feature_descriptor_sets = local_adaptive_feature_compression(binary_bytes, item)
    
    ''' RGB特征图存储 '''
    image_path = os.path.join(output_image_dir, family, sample.replace('.exe', ''))  
    to_image(local_feature_descriptor_sets, image_path)


def makefile_malimg():
    families = os.listdir(binary_dir)

    dataset = pd.DataFrame()
    for family in families:
        samples = os.listdir(os.path.join(binary_dir, family))
        os.makedirs(os.path.join(output_image_dir, family), exist_ok=True)
        for sample in samples:
            dataset = dataset._append([os.path.join(binary_dir, family, sample)])
    # 多线程并行处理, 工作线程数默认为当前系统核心数, 可通过参数nb_workers进行设置
    pandarallel.initialize(progress_bar=True)
    dataset.parallel_apply(malimg_item_processing, axis=1)

def makefile_big2015():
    families = ['Ramnit', 'Lollipop', 'Kelihos_ver3', 'Vundo', 'Simda', 'Tracur', 'Kelihos_ver1', 'Obfuscator.ACY', 'Gatak']

    for family in families:
        os.makedirs(os.path.join(output_image_dir, family), exist_ok=True)

    dataset = pd.read_csv('./datasets/BIG-2015/big2015@section_table.csv')
    dataset['section'] = dataset['section'].apply(eval)

    # 多线程并行处理, 工作线程数默认为当前系统核心数, 可通过参数nb_workers进行设置
    pandarallel.initialize(progress_bar=True)
    dataset[['file', 'id', 'imagebase', 'section_num', 'section']].parallel_apply(big2015_item_processing, axis=1)

if __name__ == '__main__':
    binary_dir = '/path/to/binary/dir'
    output_image_dir = '/path/to/output/image/dir'
    makefile_malimg()
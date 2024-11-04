package Server;

import Client.Xor_conjuction;
import Client.Xor_conjuctionXMM;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import util.GGM;
import util.Hash;
import util.tool;
import java.security.SecureRandom;
import java.io.*;
import java.util.*;

import static Client.Xor_conjuction.xtagitem.xtagitem_list;
import static Client.Xor_conjuction.xtoken;
import static Client.Xor_conjuction.xtoken_key1;

import static Client.Xor_conjuctionXMM.*;
import static Server.server.xtagitem_flag.xtagitem_flaglist;
import static util.tool.longToBytes;

public class server {
    private static final int HASHES = 3;
    private static byte[][] EMM;
    public static byte[][] resArray;
    public static int[] XORF;
    private static long K_d = 123;
    public static Element[] xtagelement;
    private static int MAX_VOLUME_LENGTH;
    private static int server_level;
    private static Random random = new Random();
    public static Element[] xflag;
    static int Try_Times = 0;
    public static Element[] xtag_key1 ;
    private static int server_DEFAULT_INITIAL_CAPACITY;
    private ArrayList<byte[]> C_key = new ArrayList<byte[]>();
    public server(){}
    public Pairing pairing = PairingFactory.getPairing("C:\\Users\\周超然\\Desktop\\XorMM-conjunction\\a.properties");
    public Element g = pairing.getG1().newRandomElement().getImmutable();


    // 定义一个类来存储 k, change, found 的值
    // 更新变量声明
    public static List<KChangeFound> KChangefound_list = new ArrayList<>();
    public static Map<Integer, KChangeFound> kToFoundMap = new HashMap<>();
    public static class KChangeFound {
        public int k;
        public int change;
        public int found;

        public KChangeFound(int k, int change, int found) {
            this.k = k;
            this.change = change;
            this.found = found;
        }
    }

    public static class xtagitem_flag {

        public static xtagitem_flag[] xtagitem_flaglist;
        public  String xSubstring_1flag;
        public  int xSubstring_2flag;

        // 构造函数
        public xtagitem_flag( String xSubstring_1flag, int xSubstring_2flag) {

            this.xSubstring_1flag = xSubstring_1flag;
            this.xSubstring_2flag = xSubstring_2flag;
        }
    }

    public server(byte[][] fp,int volume_length, int level,int DEFAULT_INITIAL_CAPACITY){
        EMM = fp;
        MAX_VOLUME_LENGTH = volume_length;
        server_level = level;
        server_DEFAULT_INITIAL_CAPACITY = DEFAULT_INITIAL_CAPACITY;
    }

    public void  Query_Xor(byte[] hash){
        for (int i = 0;i<MAX_VOLUME_LENGTH;i++ ) {
                byte[] father_Node = GGM.Tri_GGM_Path(hash, server_level, tool.TtS(i, 3, server_level));
                int t0 = GGM.Map2Range(Arrays.copyOfRange(father_Node, 1 , 9),server_DEFAULT_INITIAL_CAPACITY,0);
                int t1 = GGM.Map2Range(Arrays.copyOfRange(father_Node, 11, 19),server_DEFAULT_INITIAL_CAPACITY,1);
                int t2 = GGM.Map2Range(Arrays.copyOfRange(father_Node, 21, 29),server_DEFAULT_INITIAL_CAPACITY,2);
//                System.out.println("t0: " + t0 + " t1: " + t1 + " t2: " + t2);
//                System.out.println("EMM0: "+ Arrays.toString(EMM[t0]));
//                System.out.println("EMM1: "+ Arrays.toString(EMM[t1]));
//                System.out.println("EMM2: "+ Arrays.toString(EMM[t2]));
                byte[] res = tool.Xor(tool.Xor(EMM[t0], EMM[t1]), EMM[t2]);
                String re_s = new String(res);
//                System.out.println("res: "+Arrays.toString(res));
                C_key.add(res);
            }
//System.out.println("C_key: " + C_key);

    }


    public void  xflag(byte[] hash){
        xtag_key1 =new Element[MAX_VOLUME_LENGTH * (search_keys.length-1)];
        for (int i = 0;i<MAX_VOLUME_LENGTH * (search_keys.length-1);i++){
            Element xtagelement = xtoken[i].powZn(xtoken_key1[i]);
            xtag_key1[i] = xtagelement;
//            System.out.println("xtagxxx: " + xtag_key1[i]);
        }

        xtagitem_flaglist = new xtagitem_flag[MAX_VOLUME_LENGTH * (search_keys.length-1)];
// 现在可以将 y 数组的 Element 类型结果转换为 String

        for (int i = 0; i < MAX_VOLUME_LENGTH * (search_keys.length-1); i++) {
            String xflagString = xtag_key1[i].toString();  // 将 Element 转换为 String
            xtagitem_flaglist[i] = new xtagitem_flag(xflagString.substring(0, Math.min(30, xflagString.length())), Integer.parseInt(xflagString.substring(16, Math.min(20, xflagString.length()))));
        }
        for (int i = 0; i < MAX_VOLUME_LENGTH * (search_keys.length-1); i++) {
//            System.out.println("xtagitem_flaglist1[" + i + "]: " + xtagitem_flaglist[i].xSubstring_1flag);  // 打印转换后的 String
//            System.out.println("xtagitem_flaglist2[" + i + "]: " + xtagitem_flaglist[i].xSubstring_2flag);  // 打印转换后的 String
        }
    }

    public void DecryptXMM() {
        resArray = new byte[xtagitem_flaglist.length][];
        // 遍历 xtagitem_flaglist
        for (int i = 0; i < xtagitem_flaglist.length; i++) {
            // 获取当前的 xtagitem_flag
            String xSubstring_1flag = xtagitem_flaglist[i].xSubstring_1flag;
            int xSubstring_2flag = xtagitem_flaglist[i].xSubstring_2flag;


            // 在 xtagitem_list 中查找匹配的 k
            int k = -1;
            for (int j = 0; j < xtagitem_list.length; j++) {
                if (xtagitem_list[j].xSubstring_1.equals(xSubstring_1flag) &&
                        xtagitem_list[j].xSubstring_2 == xSubstring_2flag) {
                    k = j;
                    break;
                }
            }

            if (k == -1) {
                // 为 res 赋一个长度为 16 的随机值
                Random random = new Random();
                int q1 = random.nextInt(1023); // Generates a random number between 0 and 1022
                int q2 = random.nextInt(1023);
                int q3 = random.nextInt(1023);
                byte[] res = tool.Xor(tool.Xor(XMM[q1], XMM[q2]), XMM[q3]);
                resArray[i] = res; // 将 res 存储到 resArray 中
                continue; // 跳过当前循环，继续下一个
            }

            // 通过 k 值直接获取对应的 KChangePair
            KChangePair targetPair = Xor_conjuctionXMM.kToPairMap.get(k);

            if (targetPair == null) {
                System.out.println("在 KChangePair_list 中未找到对应的 KChangePair，对于 k = " + k);
                // 为 res 赋一个长度为 16 的随机值
                byte[] res = new byte[16];
                new SecureRandom().nextBytes(res); // 使用 SecureRandom 生成更随机的字节
                System.out.println("res 被赋予随机值：" + Arrays.toString(res));
                continue;
            }

            int foundx = targetPair.found;
            int changex = targetPair.change;

            // 初始化 t1 和 t2
            int t1 = -1;
            int t2 = -1;
            int tCount = 0;

            for (int hi = 0; hi < HASHES; hi++) {
                // 计算 t 值
//                System.out.println("xSubstring_1flag[" + k + "].xSubstring_1: " + xSubstring_1flag);
//                System.out.println("xSubstring_1flag[" + k + "].xSubstring_2: " + xSubstring_2flag);
                Integer t = Xor_conjuctionXMM.leave_map.get(xtagitem_list[k].xSubstring_1 + "," + xtagitem_list[k].xSubstring_2 + "," + hi);

                if (t == null) {
                    continue; // 跳过 null 值
                }

                if (hi == foundx) {
                    continue; // 当 hi 等于 found 时，不计算
                } else {
                    if (tCount == 0) {
                        t1 = t;
                        tCount++;
                    } else if (tCount == 1) {
                        t2 = t;
                        break; // 找到 t1 和 t2，跳出循环
                    }
                }
            }

            if (t1 != -1 && t2 != -1) {
                // 执行异或操作解密
                byte[] res = tool.Xor(tool.Xor(XMM[changex], XMM[t1]), XMM[t2]);

                // 处理解密结果，例如存储或输出
//                System.out.println("解密结果 res[" + k + "]: " + Arrays.toString(res));
                resArray[i] = res;
            } else {
                System.out.println("无法找到 t1 和 t2，对于 k = " + k);
            }
        }
        // 在循环结束后，输出 resArray
//        System.out.println("所有的 res 值：");
        for (int i = 0; i < resArray.length; i++) {
            byte[] res = resArray[i];
            if (res != null) {
//                System.out.println("resArray[" + i + "] = " + Arrays.toString(res));
            } else {
//                System.out.println("resArray[" + i + "] = null");
            }
        }
        for (int i = 0; i < resArray.length; i++) {
            Element key_valueElement = Hash.HashToZr(pairing, resArray[i]);
            key_valueElementx[i] = key_valueElement;
//            System.out.println("key_value " + i + ":" + (key_valueElementx[i]));
        }
        xtagitem_list = new Xor_conjuction.xtagitem[resArray.length];
// 现在可以将 y 数组的 Element 类型结果转换为 String

        for (int i = 0; i < resArray.length; i++) {
            String xtagString = key_valueElementx[i].toString();  // 将 Element 转换为 String
            xtagitem_list[i] = new Xor_conjuction.xtagitem(xtagString.substring(0, Math.min(10, xtagString.length())), Integer.parseInt(xtagString.substring(11, Math.min(20, xtagString.length()))));
//            System.out.println("xtagitem_list[" + i + "].xSubstring_1: " +xtagitem_list[(int)i].xSubstring_1);
//            System.out.println("xtagitem_list[" + i + "].xSubstring_2: " +xtagitem_list[(int)i].xSubstring_2);
        }
    }


    public void MappingStep3() {
        int table_size = (int) Math.floor(((resArray.length * 1.23) ) / 3);
        XORF = new int[table_size * 3];
        int MAX_VOLUME_LENGTH = (int) Math.pow(2, 5);
        int level = (int) Math.ceil(Math.log(MAX_VOLUME_LENGTH) / Math.log(3.0));//GGM Tree level for xor hash
        int arrayLength = table_size * 3;
        int blockLength = table_size;
        long[] reverseOrder = new long[arrayLength];
        byte[] reverseH = new byte[arrayLength];
        int HASHES = 3;
        int reverseOrderPos;



        do {
            reverseOrderPos = 0;
            leave_map.clear();
            GGM.clear();
            K_d = random.nextLong();
            byte[] t2count = new byte[arrayLength];
            long[] t2 = new long[arrayLength];



            for (int i = 0; i < resArray.length; i++) {
                long k = i;
                for (int hi = 0; hi < HASHES; hi++) {
                    String ys = xtagitem_list[(int)k].xSubstring_1 + "," +  xtagitem_list[(int)k].xSubstring_2;
//                    System.out.println("ys: " +ys);
                    String y0 = ys + "," + hi;
//                    System.out.println("y0: " +y0);
                    int Node, current;
                    if (leave_map.containsKey(y0)) {
                        current = leave_map.get(y0);
                    } else {
//                        byte[] xxx = Hash.Get_SHA_256((ymm_list[(int) k].key + K_d).getBytes());
//                        System.out.println("yv: " +xxx);
                        byte[] yv = GGM.Tri_GGM_Path(Hash.Get_SHA_256((xtagitem_list[(int)k].xSubstring_1 + K_d).getBytes()), level, tool.TtS((xtagitem_list[(int)k].xSubstring_2), 3, level));
                        current = GGM.Map2Range(Arrays.copyOfRange(yv, 1, 9), table_size, 0);
                        leave_map.put(y0, current);
                        Node = GGM.Map2Range(Arrays.copyOfRange(yv, 11, 19), table_size, 1);
                        leave_map.put(ys + ",1", Node);
                        Node = GGM.Map2Range(Arrays.copyOfRange(yv, 21, 29), table_size, 2);
                        leave_map.put(ys + ",2", Node);
                    }
                    int h = current;
                    t2[h] ^= k;
                    if (t2count[h] > 120) {
                        throw new IllegalArgumentException();
                    }
                    t2count[h]++;
                }
            }



            int[][] alone = new int[HASHES][blockLength];
            int[] alonePos = new int[HASHES];
            for (int nextAlone = 0; nextAlone < HASHES; nextAlone++) {
                for (int i = 0; i < blockLength; i++) {
                    if (t2count[nextAlone * blockLength + i] == 1) {
                        alone[nextAlone][alonePos[nextAlone]++] = nextAlone * blockLength + i;
                    }
                }
            }
            int found = -1;
            while (true) {
                int i = -1;
                for (int hi = 0; hi < HASHES; hi++) {
                    if (alonePos[hi] > 0) {
                        i = alone[hi][--alonePos[hi]];
                        found = hi;
                        break;
                    }
                }
                if (i == -1) {
                    break;
                }
                if (t2count[i] <= 0) {
                    continue;
                }
                long k = t2[i];
                if (t2count[i] != 1) {
                    throw new AssertionError();
                }
                --t2count[i];
                for (int hi = 0; hi < HASHES; hi++) {
                    if (hi != found) {
//                        Integer mapValue = leave_map.get(ymm_list[(int) k].key + "," + ymm_list[(int) k].counter + "," + hi);
////                        System.out.println("mapValue: " +mapValue);
//                        if (mapValue == null) {
//                            // 可以选择抛出更明确的异常或进行其他逻辑处理
//                            throw new IllegalStateException("Map does not contain the key: " + ymm_list[(int) k].key + "," + ymm_list[(int) k].counter + "," + hi);
//                        }
                        int h = leave_map.get(xtagitem_list[(int)k].xSubstring_1 + "," +  xtagitem_list[(int)k].xSubstring_2 + "," + hi);
//                        System.out.println("h: " +h);
                        int newCount = --t2count[h];
                        if (newCount == 1) {
                            alone[hi][alonePos[hi]++] = h;
                        }
                        t2[h] ^= k;
                    }
                }
                reverseOrder[reverseOrderPos] = k;
                reverseH[reverseOrderPos] = (byte) found;
                reverseOrderPos++;
            }



            Try_Times++;
        } while (reverseOrderPos != resArray.length);

// 创建一个列表来存储每次循环的记录
        List<KChangeFound> records = new ArrayList<>();
// 初始化数组，将每个元素设置为 -1，表示尚未初始化
        Arrays.fill(XORF, -1);
        for (int i = reverseOrderPos - 1; i >= 0; i--) {
            int k = (int) reverseOrder[i];
//            System.out.println("k: " +k);
            int found = reverseH[i];
            int change = -1;
//            xor.xor_list[k] = enc_list[k];
//            System.out.println("enc: " +Arrays.toString(enc_list[k]));
            int xor_x = 1;
            for (int hi = 0; hi < HASHES; hi++) {
                Integer h = leave_map.get(xtagitem_list[(int)k].xSubstring_1 + "," +  xtagitem_list[(int)k].xSubstring_2 + "," + hi);
//                System.out.println("h: " +h);
                if (h == null) {
                    // 处理null情况，可以打印日志、抛出异常，或者赋予默认值
//                    System.out.println("Key not found: " + e[i] + "," + y[i]);
                    continue; // 或者 break，或者赋予 h 一个默认值
                }
                if (found == hi) {
                    change = h;
//                    System.out.println("change: " +change);
                } else {
                    if (XORF[h] == -1) {
                        XORF[h] = random.nextInt(10000); // 生成 0 到 9999 之间的随机整数

                    }
//                    System.out.println("XORF: " +XORF[h]);
//                    System.out.println("h_h:   " + h);
                    xor_x = tool.Xorint(xor_x, XORF[h]);

//                    System.out.println("xor_x: " + Arrays.toString(xor_x));
                }
            }
            XORF[change] = xor_x;
            // 记录 k, change, found 的值
            KChangeFound record = new KChangeFound(k, change, found);
            records.add(record);
            // 将记录添加到 Map 中
            kToFoundMap.put(k, record);
        }
        // 在循环完成后，按照 k 从小到大排序
        Collections.sort(records, new Comparator<KChangeFound>() {
            @Override
            public int compare(KChangeFound o1, KChangeFound o2) {
                return Integer.compare(o1.k, o2.k);
            }
        });

// 输出排序后的数组
//        System.out.println("排序后的 k, change, found 值：");
        for (KChangeFound record : records) {
//            System.out.println("k: " + record.k + ", change: " + record.change + ", found: " + record.found);
        }

    }

    public ArrayList<byte[]> Get_C_key(){ return C_key; }
    public void Clear(){ C_key.clear();}

    public static void Store_Server(String text) {
        try {
            FileOutputStream file = new FileOutputStream("Server_"+text+".dat");
            for (int i = 0; i < EMM.length; i++) {
                file.write(EMM[i]);
            }
            file.close();
        } catch (IOException e) {
            System.out.println("Error - " + e.toString());
        }
    }



}

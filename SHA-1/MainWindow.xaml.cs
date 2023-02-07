using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace SHA_1
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void scrllInput_TextChanged(object sender, TextChangedEventArgs e)
        {
            //Resetting output boxes when new text is inputted
            errorOutput.Text = "";
            outDg.ItemsSource = null;
            scrllOutput.Text = "";
        }

        private void calculate_Click(object sender, RoutedEventArgs e)
        {
            /**************
            TEXT FORMATTING
            **************/
            String input = scrllInput.Text;
            String binaryInput = "";

            //Checking if the combo box is null, returning an error.
            ComboBoxItem ComboItem = (ComboBoxItem)inputType.SelectedItem;
            if (inputType.SelectedItem == null)
            {
                errorOutput.Text = "Please select an input type!";
                return;
            }

            //Pulling the selected combo box item.
            String selectedType = ComboItem.Content.ToString();

            //If ascii is selected, go through this method of converting to binary text.
            if (selectedType.Equals("ASCII"))
            {
                //Checking if there is no input, returning an error.
                if (input.Equals(""))
                {
                    errorOutput.Text = "Please input text!!!";
                    return;
                }

                //Converting every ascii char into binary.
                foreach (char c in input)
                {
                    binaryInput += Convert.ToString(c, 2).PadLeft(8, '0');
                }

                //Checking if the binary is less than 448 bits, returning an error otherwise.
                if(binaryInput.Length > 448)
                {
                    errorOutput.Text = "Please give a smaller input! This is larget than 448 bits :(";
                    return;
                }
            }
            //If hexadecimal is selected, go through this method of converting to binary text.
            else if (selectedType.Equals("Hexadecimal"))
            {
                //Checking if there is no input, returning an error.
                if (input.Equals(""))
                {
                    errorOutput.Text = "Please input text!!!";
                    return;
                }

                //Converting every hexadecimal char into binary.
                String unfInput = Regex.Replace(input.ToLower(), "[^0-9a-f]", "");
                for (int i = 0; i < unfInput.Length; i++)
                {
                    binaryInput += Convert.ToString(Convert.ToInt32(unfInput.Substring(i,1), 16), 2).PadLeft(4, '0');
                }

                //Checking if the binary is less than 448 bits, returning an error otherwise.
                if (binaryInput.Length > 448)
                {
                    errorOutput.Text = "Please give a smaller input! This is larger than 448 bits :(";
                    return;
                }
            }

            /**************
            MESSAGE PADDING
            **************/
            int l = binaryInput.Length; //Number of bits in the message.
            int k;
            k = 448 - (l + 1); //Calculated amount of appended zero bits to the message.

            binaryInput += "1"; //Appending "1" to the end of the message.

            //Appending k number of "0" bits to the message.
            for (int i = 0; i < k; i++)
            {
                binaryInput += "0";
            }

            //l representation in binary, appended with zeroes to the left to make a total 64-bit block, appended to the message's end
            String binaryEnd = Convert.ToString(l, 2);
            int remZeroes = 64 - binaryEnd.Length;

            for (int i = 0; i < remZeroes; i++)
            {
                binaryInput += "0";
            }
            binaryInput += binaryEnd;

            /**************
            MESSAGE PARSING
            **************/
            //Splitting the message into sixteen 32-bit words in a 1D array.
            String[] parsedBinary = new string[16];
            int parseCount = 0;
            for (int i = 0; i < 16; i++)
            {
                parsedBinary[i] = binaryInput.Substring(parseCount, 32);
                parseCount += 32;
            }

            /************
            PREPROCESSING
            ************/
            //1D array of hash values.
            String[] hashValues =
            {
                "67452301",
                "EFCDAB89",
                "98BADCFE",
                "10325476",
                "C3D2E1F0",
            };

            //1D array of the given constants K for SHA-1, given at their respective increment.
            String[] varK = new string[80];
            for (int i = 0; i < 80; i++)
            {
                if (i <= 19)
                {
                    varK[i] = "5A827999";
                }
                else if (i >= 20 && i <= 39)
                {
                    varK[i] = "6ED9EBA1";
                }
                else if (i >= 40 && i <= 59)
                {
                    varK[i] = "8F1BBCDC";
                }
                else if (i >= 60 && i <= 79)
                {
                    varK[i] = "CA62C1D6";
                }
            }

            /*********************
            SHA-1 HASH COMPUTATION
            *********************/
            /*MESSAGE SCHEDULE PREPARATION*/
            //Creating an array for the message schedule W, for all 80 rounds
            String[] varW = new string[80];
            for (int i = 0; i < 16; i++) //Setting the first 16 W values as the 16 separate parsed blocks of the message.
            {
                String hexConvert = Convert.ToUInt32(parsedBinary[i], 2).ToString("X2").PadLeft(8, '0');
                varW[i] = hexConvert;
            }

            for (int i = 15; i < varW.Length; i++) //Calculating the rest of W values according to the FIPS publication.
            {
                if (i >= 16)
                {
                    UInt32 xor = 
                        Convert.ToUInt32(varW[(i - 3)], 16) ^ 
                        Convert.ToUInt32(varW[(i - 8)], 16) ^ 
                        Convert.ToUInt32(varW[(i - 14)], 16)^ 
                        Convert.ToUInt32(varW[(i - 16)], 16);
                    varW[i] = circLeftShift(xor.ToString("X2").PadLeft(8,'0'), 1);
                }
            }

            /*VARIABLE INITIALIZATION*/
            //Initializing the variables a, b, c, d, and e, with the initial hashes, as given by the FIPS publication.
            String varA = hashValues[0];
            String varB = hashValues[1];
            String varC = hashValues[2];
            String varD = hashValues[3];
            String varE = hashValues[4];

            /*SHA-1 COMPUTATIONS*/
            //Creating a list of the Outputs class, used for the datagrid to see each variable at every round.
            List<Outputs> computation = new List<Outputs>();

            //For-loop for computing for 80 rounds.
            for (int i = 0; i < 80; i++)
            {
                //varF computation separately calculated, reducing confusion below.
                String varF = logicFunctions(varB, varC, varD, i).PadLeft(8, '0');

                //Computations as seen in the FIPS publication.
                String varT = addModulo(addModulo(addModulo(addModulo(circLeftShift(varA, 5), varF), varE), varK[i]), varW[i]).PadLeft(8, '0');
                varE = varD.PadLeft(8, '0');
                varD = varC.PadLeft(8, '0');
                varC = circLeftShift(varB, 30).PadLeft(8, '0');
                varB = varA.PadLeft(8, '0');
                varA = varT.PadLeft(8, '0');

                //Creating a temporary Outputs object, inserting all working variables into the object for the ith round.
                Outputs compTemp = new Outputs();
                {
                    compTemp.i = i;
                    compTemp.a = varA;
                    compTemp.b = varB;
                    compTemp.c = varC;
                    compTemp.d = varD;
                    compTemp.e = varE;
                    compTemp.f = varF;
                    compTemp.w = varW[i];
                }
                computation.Add(compTemp); //Adding the temporary object into the list of all outputs for each round.
            }
            //After all rounds have been computed, the datagrid of all variables in every round will show the calculated list.
            outDg.ItemsSource = computation;

            //Computing the additions for the final hash values.
            String h0 = addModulo(hashValues[0], varA);
            String h1 = addModulo(hashValues[1], varB);
            String h2 = addModulo(hashValues[2], varC);
            String h3 = addModulo(hashValues[3], varD);
            String h4 = addModulo(hashValues[4], varE);
            
            //Appending h0 to h4 together, resulting in the 160-bit message digest of the input, giving the hashed hex final calculation.
            scrllOutput.Text = h0 + " " + h1 + " " + h2 + " " + h3 + " " + h4 + " ";
        }

        String circLeftShift (String hex, int cycles)
        {
            /************************************************************************************************************************
            The ROTL, or Circular Left Shift operation as seen in the FIPS publication. Takes the first bit and moves it to the back.
            ************************************************************************************************************************/
            
            //Converts the 8 character hex input into a 32-bit binary number.
            String bits = Convert.ToString(Convert.ToUInt32(hex, 16), 2).PadLeft(32, '0');
            for (int i = 0; i < cycles; i++) //For-loop according to how many shift cycles is given.
            {
                String tempString = bits.Substring(1, bits.Length - 1); //Creates a temp string of the binary number without the first bit.
                String tempChar = bits[0].ToString(); //Creates a temp char of the first bit.
                bits = tempString + tempChar; //Appends the first bit to the back of the temp string.
            }
            hex = Convert.ToInt32(bits, 2).ToString("X2").PadLeft(8, '0'); //Converts the new binary string back into hex and padding it.
            return hex;
        }

        String logicFunctions (String x, String y, String z, int t)
        {
            /****************************************************************************************************************************************
            Sequence of logical functions given by the FIPS publication, taking 32-bit words x, y, and z, determining a function with the t'th round.
            ****************************************************************************************************************************************/

            //Converting the 32-bit hex words into unsigned integers.
            UInt32 uX = Convert.ToUInt32(x, 16);
            UInt32 uY = Convert.ToUInt32(y, 16);
            UInt32 uZ = Convert.ToUInt32(z, 16);

            if (t <= 19) //The Ch function, for when 0 <= t <= 19. (x AND y) XOR (COMPx AND z).
            {
                String ch;
                ch = ((uX & uY) ^ ((~uX) & uZ)).ToString("X2");
                return ch;
            }
            else if ((t >= 20 && t <= 39) || (t >= 60 && t <= 79)) //The Parity function, for when 20 <= t <= 39 and 60 <= t <= 79. (x AND y) XOR (x AND z) XOR (y AND z).
            {
                String parity;
                parity = (uX ^ uY ^ uZ).ToString("X2");
                return parity;
            }
            else if (t >= 40 && t <= 59) //The Maj function, for when 40 <= t <= 59. (x XOR y XOR z).
            {
                String maj;
                maj = ((uX & uY) ^ (uX & uZ) ^ (uY & uZ)).ToString("X2");
                return maj;
            }
            else //Null return if anything else.
            {
                return null;
            }
        }

        String addModulo (String x, String y)
        {
            /***************************************************************************************
            Function for addition, as given by the FIPS publication that it is performed modulo 2^32.
            ***************************************************************************************/

            //Converting the 32-bit hex words into unsigned integers (z is the output).
            int uX = Convert.ToInt32(x, 16);
            int uY = Convert.ToInt32(y, 16);
            int uZ;

            uZ = (int)((uX + uY) % 4294967296); //Adding X and Y, and performing modulo 2^32, or 4294967296.
            return uZ.ToString("X2"); //Returning the hex result.
        }
    }

    public class Outputs
    {
        /****************************************************
        Used to output every working variable at every round.
        ****************************************************/
        public int i { get; set; }
        public String a { get; set; }
        public String b { get; set; }
        public String c { get; set; }
        public String d { get; set; }
        public String e { get; set; }
        public String f { get; set; }
        public String w { get; set; }
    }
}
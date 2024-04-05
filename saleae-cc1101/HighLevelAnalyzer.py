from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from saleae.data import GraphTimeDelta, GraphTime

BIT0 = 0b00000001
BIT1 = 0b00000010
BIT2 = 0b00000100
BIT3 = 0b00001000
BIT4 = 0b00010000
BIT5 = 0b00100000
BIT6 = 0b01000000
BIT7 = 0b10000000

class Hla(HighLevelAnalyzer):

    packet_timeout = NumberSetting(label='Packet Timeout [us]', min_value=0.1, max_value=1000)
    f_xosc = NumberSetting(label='Crystal Oscillator [MHz]', min_value=10, max_value=50)
    try: 
        # NumberSettings class doesn't have an __int__ ?
        f_xosc = int(f_xosc) * 1000000
    except:
        print ('warning NumberSetting integer cast failed.\nignoring f_xsoc, using a default')
        f_xosc = 26000000
        pass
    
    origin_time = None
    start_time = None
    end_time = None
    freq = 0
    datarate_e = 0
    chanspc_e = 0
    tx = bytearray()
    rx = bytearray()

    # Base output formatting options:
    result_types = {
        'error': {
            'format': 'Error!'
        },
    }

    def __init__(self):
        self.result_types["message"] = {
            'format': '{{data.text}}'
        }

    def regValue(self, addr, value):
        if ( addr == 0x07 ): # PKTCTRL1
            ret = ".PQT:" + hex((value&(BIT7|BIT6|BIT5))>>5) + ' '
            ret += ('','.CRC_AUTOFLUSH ')[value&BIT3!=0]
            ret += ('','.APPEND_STATUS ')[value&BIT2!=0]
            ret += ".ADDR_CHK:" + hex((value&(BIT1|BIT0)))
        elif ( addr == 0x08 ): # PKTCTRL0
            ret = ('','.WHITE_DATA ')[value&BIT6!=0]
            pktFormat = {0b00:'NORM',0b01:'SYNC_GDO',0b10:'PN9',0b11:'ASYNC_GDO'}
            ret += ".PKT_FORMAT:" + pktFormat.get((value&(BIT5|BIT4))>>4) + ' '
            ret += ('','.CRC_EN ')[value&BIT2!=0]
            lenConfig = {0b00:'FIX',0b01:'VAR',0b10:'INF',0b11:'3'}
            ret += ".LENGTH_CONFIG:" + lenConfig.get((value&(BIT1|BIT0)))
        elif ( addr == 0x0D ): # FREQ2
            value = 0x23
            self.freq = value<<16
            ret = ":%02X"%(value)
        elif ( addr == 0x0E ): # FREQ1
            value = 0x31
            self.freq |= value<<8
            ret = ":%02X"%(value)
        elif ( addr == 0x0F ): # FREQ0
            value = 0x3B
            freq = self.freq | value
            freq *= (self.f_xosc / pow(2,16))
            ret = '.FREQ:%d' %(freq)
        elif ( addr == 0x10 ): # MDMCFG4
            self.datarate_e = value&(BIT3|BIT2|BIT1|BIT0)
            ret = ":%02X"%(value)
        elif ( addr == 0x11 ): # MDMCFG3
            datarate_m = value
            dataRate = ((256+datarate_m)*pow(2,self.datarate_e)) / pow(2,28) * self.f_xosc
            ret = ".DATARATE:%d" % (dataRate)
        elif ( addr == 0x12 ): # MDMCFG2
            ret = ('','.DEM_DCFILT_OFF ')[value&BIT7!=0]
            modFormat = {0b000:'2FSK',0b001:'GFSK',0b010:'2',0b011:'OOK',0b100:'4FSK',0b101:'5',0b110:'6',0b111:'MSK',}
            ret += ".MOD_FORMAT:" + modFormat.get((value&(BIT6|BIT5|BIT4))>>4) + ' '
            ret += ('','.MANCHESTER_EN ')[value&BIT3!=0]
            ret += ".SYNC_MODE:" + hex(value&(BIT2|BIT1|BIT0))
        elif ( addr == 0x13 ): # MDMCFG1
            ret = ('','.FEC_EN ')[value&BIT7!=0]
            numPreamble = {0b000:'2',0b001:'3',0b010:'4',0b011:'6',0b100:'8',0b101:'12',0b110:'16',0b111:'24',}
            ret += ".NUM_PREAMBLE:" + numPreamble.get((value&(BIT6|BIT5|BIT4))>>4) + ' '
            self.chanspc_e = value&(BIT1|BIT0)
        elif ( addr == 0x14 ): # MDMCFG1
            chanspc_m = value
            chanspc = (self.f_xosc / pow(2,18)) * (256+chanspc_m) * pow(2,self.chanspc_e)
            ret = ".CHANSPC:%d" % (chanspc)
        elif ( addr == 0x15 ): # DEVIATN
            dev_e = (value&(BIT6|BIT5|BIT4))>>4
            dev_m = value&(BIT2|BIT1|BIT0)
            deviation = (self.f_xosc / pow(2,17)) * (8+dev_m) * pow(2,dev_e)
            ret = ".DEV:%d" % deviation
        elif ( addr == 0x35 ): # MARCSTATE
            mState = {0:'SLEEP',1:'IDLE',2:'XOFF',3:'VCOON_MC',4:'REGON_MC',5:'MANCAL',6:'VCOON',7:'REGON',8:'STARTCAL',9:'BWBOOST',
                      10:'FS_LOCK',11:'IFADCON',12:'ENDCAL',13:'RX',14:'RX_END',15:'RX_RST',16:'TXRX_SW',17:'RXFIFO_OVER',18:'FSTXON',19:'TX',
                      20:'TX_END',21:'RXTX_SW',22:'TXFIFO_UNDER'}
            ret = mState.get(value)
        else:
            return ":%02X"%(value)
        return " " + ret

    def regName(self, b):
        lut = {0x00:'IOCFG2',0x01:'IOCFG1',0x02:'IOCFG0',0x03:'FIFOTHR',0x04:'SYNC1',0x05:'SYNC0',0x06:'PKTLEN',0x07:'PKTCTRL1',0x08:'PKTCTRL0',
               0x0A:'CHAN',0x0D:'FREQ2',0x0E:'FREQ1',0x0F:'FREQ0',
               0x10:'MDMCFG0',0x11:'MDMCFG1',0x12:'MDMCFG2',0x13:'MDMCFG1',0x14:'MDMCFG0',0x15:'DEVIATN', 0x29:'FSTEST',
               0x30:'SRES!',0x31:'SFSTXON',0x33:'SCAL',0x34:'SRX',0x35:'STX',0x36:'SIDLE',0x3a:'SFRX',0x3b:'SFTX',0x3e:'PATABLE',0x3f:'FIFO'}
        ret = lut.get(b)
        if ( ret ):
            return ret
        else:
            return "%02X"%(b)

    def regNameAlt(self, b):
        lut = {0x30:'PARTNUM',0x31:'VERSION',0x32:'FREQEST',0x33:'LQI',0x34:'RSSI',0x35:'MSTATE',0x36:'WORTIME1',0x37:'WORTIME0',
               0x38:'PKTSTATUS',0x39:'VCO_VC_DAC',0x3A:'TXBYTES',0x3B:'RXBYTES',0x3C:'RCCTRL1',0x3D:'RCCTRL0'}
        ret = lut.get(b)
        if ( ret ):
            return ret
        else:
            return self.regName(b)

    def decode(self, frame: AnalyzerFrame):
        
        if frame.type != "result":
            return
        if len(frame.data)==0:
            return
        if not "mosi" in frame.data.keys():
            return
        if not "miso" in frame.data.keys():
            return
        
        gap_time = GraphTimeDelta(microsecond=self.packet_timeout)
        ret = None

        if not self.origin_time:
            self.origin_time = frame.start_time
            
        if not self.start_time:
            # initial case, first packet
            self.start_time = frame.start_time
            self.end_time = frame.end_time
            self.tx += bytes(frame.data["mosi"])
            self.rx += bytes(frame.data["miso"])

        elif (frame.start_time - self.end_time) > gap_time :
            # consider frames further apart than this separate messages
            text = "?"
            if (len(self.tx)>0):
                b = self.tx[0]
                addr = b & 0x3F
                burst = b & 0x40 
                read = b & 0x80 
                # print ( hex(b), hex(addr), hex(read), hex(burst) ),
                # print ("tx:", " ".join("{:02x}".format(c) for c in self.tx))
                # print ("rx:", " ".join("{:02x}".format(c) for c in self.rx))

                if ( addr == 0x3e ):
                    if ( read ):
                        text = "R PATABLE"
                        for b in self.rx[1:]:
                            text += ' ' + "%02X"%(b)
                    else:
                        text = "W PATABLE"
                        for b in self.tx[1:]:
                            text += ' ' + "%02X"%(b)

                elif ( addr == 0x3f ):
                    if ( read ):
                        text = "R RXFIFO"
                        for b in self.rx[1:]:
                            text += ' ' + "%02X"%(b)
                    else:
                        text = "W TXFIFO"
                        for b in self.tx[1:]:
                            text += ' ' + "%02X"%(b)
                else:
                    if ( burst ):
                        if ( read ):
                            text = "R"
                            for b in self.rx[1:]:
                                text += ' ' + self.regNameAlt(addr) + self.regValue(addr,b)
                                addr += 1
                        else:
                            text = "W"
                            for b in self.tx[1:]:
                                text += ' ' + self.regNameAlt(addr) + self.regValue(addr,b)
                                addr += 1
                    else:
                        if ( read ):
                            if (len(self.tx)<2):
                                text = 'R CMD ' + self.regName(addr)
                            else:
                                text = 'R ' + self.regName(addr) + self.regValue(addr,self.rx[1])
                        else:    
                            if (len(self.tx)<2):
                                text = 'CMD ' + self.regName(addr)
                            else:
                                text = 'W ' + self.regName(addr) + self.regValue(addr,self.tx[1])

                if 'FREQ' in text or 'TXFIFO' in text:
                    if not '4E 03' in text and not 'UNDER' in text:
                        timestamp = "{:.2f}ms ".format( float(self.start_time - self.origin_time) * 1000.0 )
                        print (timestamp + text)
                ret = AnalyzerFrame('message', self.start_time, self.end_time, {'text': text})
            self.start_time = frame.start_time
            self.end_time = frame.end_time
            self.tx = []
            self.rx = []
            
        self.tx += bytes(frame.data["mosi"])
        self.rx += bytes(frame.data["miso"])
            
        self.end_time = frame.end_time
        return ret
        

                        

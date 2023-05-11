'''
Created on 18.09.2022

@author: Ulrich Schwardmann, Göttingen
'''
import sys
import logging

class config(object):
    '''
    classdocs
    '''

    def __init__(self):
        '''
        Constructor
        '''
        logging.basicConfig(
            # level=logging.INFO,
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(name)s: %(message)s',
            stream=sys.stderr,
        )
   
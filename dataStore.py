# Copyright (C) 2016 Santiago R.R. <santiagorr@riseup.net>
#
# This file is part of traIXroute.
#
# traIXroute is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# traIXroute is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with traIXroute.  If not, see <http://www.gnu.org/licenses/>.

import os
import json

class dataStore():

    """
    Reads a ripe traIXroute processed file
    """
    def load_ripe (self, ripe_traixroute_file):
        self.ripe_traixroute_file = ripe_traixroute_file
        with open(ripe_traixroute_file, 'r') as outfile:
            self.traceroutes = json.load(outfile)

    def get_ripe (self):
        return self.traceroutes

    def addJediData(self, src_prb_id, dst_prb_id, entry_ixp):
        # TODO: before dumping, check if traixroute doesn't exist yet
        for jd in jedidata :
            if jd.__contains__("src_prb_id") and jd.__contains__("dst_prb_id"):
                if jd["src_prb_id"] == src_prb_id and jd["dst_prb_id"] == dst_prb_id :
                    jd["traixroute"] = entry_ixp

    def save(self, msm_id):
        JEDI_RESULT_DIR = os.path.dirname(self.ripe_traixroute_file) + "/results"
        JEDI_RESULT_FILE = os.path.abspath(JEDI_RESULT_DIR+"/msm."+str(msm_id)+".json")

        with open(JEDI_RESULT_FILE, mode='w') as fjedijson:
            json.dump([], fjedijson)
        with open(JEDI_RESULT_FILE, mode='w') as fjedijson:
            json.dump(jedidata, fjedijson, indent=2)

    def __init__():
        self.ripe_traixroute_file = ""
        self.traceroutes = []

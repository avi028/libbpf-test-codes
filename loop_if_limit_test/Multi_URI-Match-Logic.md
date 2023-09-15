Registration URI's for AMF-AUSF Communication:
* PUT /nausf-auth/v1/ue-authentications/hex(8)-hex(4)-hex(4)-hex(4)-hex(12)/5g-aka-confirmation 
* DELETE /nausf-auth/v1/ue-authentications/hex(8)-hex(4)-hex(4)-hex(4)-hex(12)/5g-aka-confirmation
* DELETE /nausf-auth/v1/ue-authentications/hex(8)-hex(4)-hex(4)-hex(4)-hex(12)/eap-session
* POST /nausf-auth/v1/ue-authentications
* POST /nausf-auth/v1/ue-authentications/hex(8)-hex(4)-hex(4)-hex(4)-hex(12)/eap-session 
* POST /nausf-auth/v1/ue-authentications/deregister 
    

                                                                AMF-AUSF (Registration process)
                                ______________________________________ | _______________________________
                               |                                       |                                |   
                            POST                                    DELETE                              PUT 
                            |                                          |                                 |
           -------------------------------                  ----------------------                      ---
           |        |                     |                 |                     |                      |
          " "     " /hex(8)-hex(4)-   "deregister"         "5g-aka-             "eap-session"           "5g-aka-
                    hex(4)-hex(4)-                          confirmation"                                confirmation"
                    hex(12)
                    /eap-session "



#NOTE:

1. hex(8)-hex(4)-hex(4)-hex(4)-hex(12) ~ 36 Byte to skip if no deep inspection wanted
2. Assign ID's as the match function pops the uri;

    * /nausf-auth/v1/ue-authentications - 0
    * /nausf-auth/v1/ue-authentications/deregister - 1
    * /nausf-auth/v1/ue-authentications/hex(8)-hex(4)-hex(4)-hex(4)-hex(12)/eap-session - 2
    * /nausf-auth/v1/ue-authentications/hex(8)-hex(4)-hex(4)-hex(4)-hex(12)/5g-aka-confirmation - 3

3. Protocol commmands will have predefined keys.
    * PUT - 4 
    * POST - 3
    * DELETE -5

4. KEYS : for the given set of uri's - [URI ID]\*10+[Protocol ID]

    * 03 - POST /nausf-auth/v1/ue-authentications
    * 23 - POST /nausf-auth/v1/ue-authentications/hex(8)-hex(4)-hex(4)-hex(4)-hex(12)/eap-session
    * 13 - POST /nausf-auth/v1/ue-authentications/deregister
    * 34 - PUT /nausf-auth/v1/ue-authentications/hex(8)-hex(4)-hex(4)-hex(4)-hex(12)/5g-aka-confirmation 
    * 35 - DELETE /nausf-auth/v1/ue-authentications/hex(8)-hex(4)-hex(4)-hex(4)-hex(12)/5g-aka-confirmation 
    * 25 - DELETE /nausf-auth/v1/ue-authentications/hex(8)-hex(4)-hex(4)-hex(4)-hex(12)/eap-session 



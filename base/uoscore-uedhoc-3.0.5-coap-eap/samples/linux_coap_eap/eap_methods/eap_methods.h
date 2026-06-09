#ifndef EAP_METHODS_H

    #define EAP_METHODS_H

    typedef enum {
        EAP__EDHOC, EAP__PSK 
    } EAP__METHOD;

    /**
    * @brief	Method that returns the number of iterations to be done for a specific EAP method
    * @param	method	EAP method selected
    * @retval	The number of iterations corresponding to the EAP method exchange
    */
    int eap_get_iterations(EAP__METHOD method);

#endif
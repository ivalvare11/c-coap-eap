#ifndef OSCORE_CONTEXT_H

    #define OSCORE_CONTEXT_H

    /**
     * @brief   Creates the OSCORE context from the corresponding identifiers and the MSK key
     * @param   c_ctx           Pointer to the context to be created
     * @param   sender_id       Sender ID required for the OSCORE Sender Context
     * @param   recipient_id    Recipient ID required for the OSCORE Recipient Context
     * @param   msk_key         Pointer to the MSK key used to obtain the master secret/salt
     * @retval  OK if everything was successful
     */
    enum err create_oscore_context(struct context *c_ctx, uint8_t sender_id, uint8_t recipient_id, uint8_t *msk_key);

#endif
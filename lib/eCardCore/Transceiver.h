/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if !defined(__TRANSCEIVER_INCLUDED__)
#define __TRANSCEIVER_INCLUDED__

#include <queue>
#include <vector>

/**
 * @note Classes using this template should overwrite and implement one transceive function
 */
template <class S, class R> class Transceiver
{
    public:
        virtual R transceive(const S& cmd) = 0;
        virtual std::vector<R> transceive(const std::vector<S> &cmds) = 0;
};

template <class S, class R> class IndividualTransceiver: public Transceiver<S, R>
{
    public:
        virtual R transceive(const S& cmd) = 0;
        virtual std::vector<R> transceive(const std::vector<S> &cmds)
        {
            std::vector<R> resps;
            for (size_t i = 0; i < cmds.size(); i++)
                resps.push_back(this->transceive(cmds[i]));
            return resps;
        };
};

template <class S, class R> class BatchTransceiver: public Transceiver<S, R>
{
    public:
        virtual R transceive(const S& cmd) {
            std::vector<S> cmds;
            cmds.push_back(cmd);
            std::vector<R> resps = this->transceive(cmds);
            return resps.front();
        };
        virtual std::vector<R> transceive(const std::vector<S> &cmds) = 0;
};

#endif

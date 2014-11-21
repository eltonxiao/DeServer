#pragma once
#include <boost/shared_ptr.hpp>
#include "DeLauncherIf.h"

class DecodeEngine;
class BulletinBoardIf;

class DeLauncherRemote : public DeLauncherIf
{
public:
	DeLauncherRemote(const boost::shared_ptr<BulletinBoardIf>& board) : bboard_(board) {}
	virtual ~DeLauncherRemote();
	virtual DecodeEngine *LaunchDEngine(uint16_t *pport);

private:
	boost::shared_ptr<BulletinBoardIf> bboard_;
};


#pragma once
#include <boost/shared_ptr.hpp>
#include "DeLauncherIf.h"

namespace dengine {
	class DecodeEngineIf;
	class BulletinBoardIf;
}
using namespace dengine;

class DeLauncherRemote : public DeLauncherIf
{
public:
	DeLauncherRemote(const boost::shared_ptr<BulletinBoardIf>& board) : bboard_(board) {}
	virtual ~DeLauncherRemote();
	virtual DecodeEngineIf *LaunchDEngine(uint16_t *pport);

private:
	boost::shared_ptr<BulletinBoardIf> bboard_;
};


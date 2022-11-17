#include "attest_result_info.h"

namespace OHOS {
namespace DevAttest {
bool AttestResultInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(authResult_)) {
        return false;
    }
    if (!parcel.WriteInt32(softwareResult_)) {
        return false;
    }
    if (!parcel.WriteString(ticket_)) {
        return false;
    }
    return true;
}

sptr<AttestResultInfo> AttestResultInfo::Unmarshalling(Parcel &parcel)
{
    sptr<AttestResultInfo> ptr = (std::make_unique<AttestResultInfo>()).release();
    if (ptr == nullptr) {
        return nullptr;
    }
    if (!parcel.ReadInt32(ptr->authResult_) || !parcel.ReadInt32(ptr->softwareResult_) ||
        !parcel.ReadString(ptr->ticket_)) {
        return nullptr;
    }
    return ptr;
}
}
}
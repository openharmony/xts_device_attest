#ifndef ATTEST_RESULT_INFO_H
#define ATTEST_RESULT_INFO_H

#include "parcel.h"
#include <string>
#include <list>

namespace OHOS {
namespace DevAttest {
class AttestResultInfo : public Parcelable {
public:
    int32_t authResult_ = -1;
    int32_t softwareResult_ = -1;
    std::string ticket_;

    virtual bool Marshalling(Parcel &parcel) const override;
    static sptr<AttestResultInfo> Unmarshalling(Parcel &parcel);
};
} // end of DevAttest
} // end of OHOS
#endif
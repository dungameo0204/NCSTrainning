#pragma once
#include "PeReader.h"

class RuleMatcher {
public:
    // Trả về số điểm nguy hiểm của Nhóm A
    static int EvaluateGroupA(const PeReader& reader);
    static int EvaluateGroupB(const PeReader& reader);
    static int EvaluateGroupC(const PeReader& reader);
    static float EvaluateGroupD(const PeReader& reader);
    static float EvaluateGroupE(const PeReader& reader);
private:
    // Hàm phụ trợ: Kiểm tra một số có phải là lũy thừa của 2 không (Power of Two)
    static bool IsPowerOfTwo(DWORD x);
};
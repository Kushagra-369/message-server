export const ValidName = (name: string) => {
    console.log(name)
    const NameRegex = /^[A-Za-z ]+$/;
    return NameRegex.test(name);
}

export const ValidEmail = (email: string) => {
    const EmailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return EmailRegex.test(email);
}

export const ValidPassword = (password: string) => {
    const PasswordRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*?&]{8,}$/;
    return PasswordRegex.test(password);
}

export const ValidAddress = (address: string) => {
    const AddressRegex = /^[A-Za-z0-9\s,.\-\/]+$/;
    return AddressRegex.test(address);
}

export const ValidPhone = (phone: string) => {
    const PhoneRegex = /^[\+]?[(]?[0-9]{1,4}[)]?[-\s\.0-9]{8,15}$/;
    return PhoneRegex.test(phone);
}

export const ValidOccupation = (occupation: string) => {
    const OccupationRegex = /^[A-Za-z\s\-\']+$/;
    return OccupationRegex.test(occupation);
}

export const ValidQualification = (qualification: string) => {
    const QualificationRegex = /^[A-Za-z0-9\s\-\.\(\)]+$/;
    return QualificationRegex.test(qualification);
}

export const ValidTransactionId = (transactionId: string) => {
    const TransactionRegex = /^[A-Za-z0-9\-_]+$/;
    return TransactionRegex.test(transactionId);
}

// export const ValidDate = (date:any) => {
//     return date instanceof Date && !isNaN(date);
// }
export const ValidAmount = (amt: string) => {
    const AmountRegex = /^[0-9]+$/;
    return AmountRegex.test(amt);
}
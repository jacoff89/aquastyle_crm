/**
 * A phone as it is stored ("+79123456789") written the way people read it: "+7 912 345-67-89".
 * A foreign number, or anything that is not in the stored form, is shown as it is.
 */
export const formatPhone = (phone) => {
    if (!phone) {
        return '';
    }

    const match = /^\+7(\d{3})(\d{3})(\d{2})(\d{2})$/.exec(phone);

    return match ? `+7 ${match[1]} ${match[2]}-${match[3]}-${match[4]}` : phone;
};

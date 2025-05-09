package ru.rtln.common.util;

import lombok.NoArgsConstructor;

import static lombok.AccessLevel.PRIVATE;

/**
 * Класс для работы со строками в приложении.
 */
@NoArgsConstructor(access = PRIVATE)
public class StringUtil {

    public static String getCapitalizeText(String text) {
        String trimmed = text.trim();
        return trimmed.substring(0, 1).toUpperCase() +
               trimmed.substring(1).toLowerCase();
    }
}


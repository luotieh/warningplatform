import { areaList } from '@vant/area-data';

type AreaOption = {
  label: string;
  value: string;
  children?: AreaOption[];
};

const provinceList = areaList.province_list;
const cityList = areaList.city_list;
const countyList = areaList.county_list;

export const regionOptions: AreaOption[] = Object.entries(provinceList).map(([provinceCode, provinceName]) => {
  const cityPrefix = provinceCode.slice(0, 2);
  const cities = Object.entries(cityList)
    .filter(([cityCode]) => cityCode.startsWith(cityPrefix))
    .map(([cityCode, cityName]) => {
      const countyPrefix = cityCode.slice(0, 4);
      const counties = Object.entries(countyList)
        .filter(([countyCode]) => countyCode.startsWith(countyPrefix))
        .map(([countyCode, countyName]) => ({ label: countyName, value: countyCode }));

      return { label: cityName, value: cityCode, children: counties };
    });

  return { label: provinceName, value: provinceCode, children: cities };
});

export function regionLabelFromCode(code?: null | string) {
  if (!code) return '';

  const provinceName = provinceList[`${code.slice(0, 2)}0000`];
  const cityName = cityList[`${code.slice(0, 4)}00`];
  const countyName = countyList[code];

  return [provinceName, cityName, countyName].filter(Boolean).join(' ');
}

export function regionCodeFromLabel(label?: null | string) {
  if (!label) return null;

  const names = label.split(/[\s/,-]+/).filter(Boolean);
  const countyName = names.at(-1);
  if (!countyName) return null;

  const provinceName = names[0];
  const cityName = names.length > 2 ? names[1] : undefined;

  const matched = Object.entries(countyList).find(([code, name]) => {
    if (name !== countyName) return false;
    const provinceCode = `${code.slice(0, 2)}0000`;
    const cityCode = `${code.slice(0, 4)}00`;
    if (provinceName && provinceList[provinceCode] !== provinceName) return false;
    if (cityName && cityList[cityCode] !== cityName) return false;
    return true;
  });

  return matched?.[0] ?? null;
}

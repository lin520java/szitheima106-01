package com.itheima.health.dao;

import com.github.pagehelper.Page;
import com.itheima.health.pojo.CheckItem;

import java.util.List;

public interface CheckItemDao {
    /**
     * 查询所有检查项
     * @return
     */
    List<CheckItem> findAll();

    /**
     * 添加检查项
     * @param checkItem
     */
    void add(CheckItem checkItem);

    /**
     * 条件查询
     * @param queryString
     * @return
     */
    Page<CheckItem> findByCondition(String queryString);

    /**
     * 通过id查询
     * @param id
     * @return
     */
    CheckItem findById(int id);

    /**
     * 修改检查项
     * @param checkItem
     */
    void update(CheckItem checkItem);

    /**
     * 统计使用了这个检查项的个数
     * @param id
     * @return
     */
    int findCountByCheckItemId(int id);

    /**
     * 删除
     * @param id
     */
    void deleteById(int id);
}

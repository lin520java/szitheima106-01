package com.itheima.health.controller;

import com.alibaba.dubbo.config.annotation.Reference;
import com.itheima.health.constant.MessageConstant;
import com.itheima.health.entity.PageResult;
import com.itheima.health.entity.QueryPageBean;
import com.itheima.health.entity.Result;
import com.itheima.health.pojo.CheckGroup;
import com.itheima.health.pojo.CheckItem;
import com.itheima.health.service.CheckGroupService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/checkgroup")
public class CheckGroupController {

    @Reference
    private CheckGroupService checkGroupService;

    /**
     * 添加检查组
     * @param checkgroup 检查组信息
     * @param checkitemIds 选中的检查项id数组
     * @return
     */
    @PostMapping("/add")
    public Result add(@RequestBody CheckGroup checkgroup, Integer[] checkitemIds){
        // 调用服务 添加检查组
        checkGroupService.add(checkgroup, checkitemIds);
        return new Result(true, MessageConstant.ADD_CHECKGROUP_SUCCESS);
    }

    /**
     * 检查组的分页查询
     * @param queryPageBean
     * @return
     */
    @PostMapping("/findPage")
    public Result findPage(@RequestBody QueryPageBean queryPageBean){
        // 调用服务 分页查询
        PageResult<CheckGroup> pageResult = checkGroupService.findPage(queryPageBean);
        return new Result(true, MessageConstant.QUERY_CHECKGROUP_SUCCESS,pageResult);
    }

    /**
     * 通过id查询检查组
     */
    @GetMapping("/findById")
    public Result findById(int id){
        CheckGroup checkGroup = checkGroupService.findById(id);
        return new Result(true, MessageConstant.QUERY_CHECKGROUP_SUCCESS,checkGroup);
    }

    /**
     * 通过检查组id查询选中的检查项id
     * @param id
     * @return
     */
    @GetMapping("/findCheckItemIdsByCheckGroupId")
    public Result findCheckItemIdsByCheckGroupId(int id){
        // 通过检查组id查询选中的检查项id集合
        List<Integer> checkItemIds = checkGroupService.findCheckItemIdsByCheckGroupId(id);
        return new Result(true, MessageConstant.QUERY_CHECKITEM_SUCCESS,checkItemIds);
    }

    /**
     * 修改检查组
     * @param checkgroup 检查组信息
     * @param checkitemIds 选中的检查项id数组
     * @return
     */
    @PostMapping("/update")
    public Result update(@RequestBody CheckGroup checkgroup, Integer[] checkitemIds){
        // 调用服务 修改检查组
        checkGroupService.update(checkgroup, checkitemIds);
        return new Result(true, MessageConstant.EDIT_CHECKGROUP_SUCCESS);
    }

    /**
     * 通过id删除检查组
     * @param id
     * @return
     */
    @PostMapping("/deleteById")
    public Result deleteById(int id){
        // 调用服务删除
        checkGroupService.deleteById(id);
        return new Result(true, MessageConstant.DELETE_CHECKGROUP_SUCCESS);
    }

    /**
     * 查询所有的检查组
     * @return
     */
    @GetMapping("/findAll")
    public Result findAll(){
        List<CheckGroup> list = checkGroupService.findAll();
        return new Result(true, MessageConstant.QUERY_CHECKGROUP_SUCCESS,list);
    }

}
